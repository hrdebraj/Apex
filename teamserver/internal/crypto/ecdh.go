package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

// hkdfLabel is the context info string used in HKDF expansion.
// Must match the agent constant "apex-c2-v1".
const hkdfLabel = "apex-c2-v1"

// P256 curve — matches the agent's BCRYPT_ECDH_P256_ALGORITHM.
var p256 = ecdh.P256()

// GenerateKeypair generates an ephemeral ECDH-P256 key pair.
// Returns (private key, 65-byte uncompressed public key, error).
// The 65-byte public key is what the agent understands: 0x04 || X[32] || Y[32].
func GenerateKeypair() (*ecdh.PrivateKey, []byte, error) {
	priv, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH-P256 GenerateKey: %w", err)
	}
	pub := priv.PublicKey().Bytes() // always 65 bytes for P-256 uncompressed
	return priv, pub, nil
}

// DeriveSessionKey computes the ECDH-P256 shared secret from serverPriv and the
// agent's 65-byte uncompressed public key, then derives a 32-byte AES-256
// session key via HKDF-SHA-256(shared, nonce, "apex-c2-v1").
//
// The shared secret input to HKDF is the SHA-256 hash of the X-coordinate of
// the DH result (matching the agent's BCRYPT_KDF_HASH + SHA-256 derivation).
func DeriveSessionKey(serverPriv *ecdh.PrivateKey, agentPub65 []byte, nonce [32]byte) ([32]byte, error) {
	var key [32]byte

	agentPubKey, err := p256.NewPublicKey(agentPub65)
	if err != nil {
		return key, fmt.Errorf("parse agent public key: %w", err)
	}

	// ECDH: shared = X-coord of serverPriv · agentPub  (raw bytes from Go = X[32])
	sharedBytes, err := serverPriv.ECDH(agentPubKey)
	if err != nil {
		return key, fmt.Errorf("ECDH: %w", err)
	}

	// Agent uses BCRYPT_KDF_HASH + SHA-256 which hashes the X-coordinate.
	// Match that: use SHA-256(sharedBytes) as IKM for HKDF.
	hashedShared := sha256.Sum256(sharedBytes)

	r := hkdf.New(sha256.New, hashedShared[:], nonce[:], []byte(hkdfLabel))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// GCMEncrypt encrypts plaintext with AES-256-GCM using key.
// Returns base64( nonce[12] || ciphertext || tag[16] ).
func GCMEncrypt(key [32]byte, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	blob := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// GCMDecrypt decrypts a base64-encoded blob produced by GCMEncrypt or the agent.
func GCMDecrypt(key [32]byte, b64blob string) ([]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(b64blob)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("blob too short")
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SessionStore holds per-agent AES-256 session keys.
type SessionStore struct {
	mu   sync.RWMutex
	keys map[string][32]byte
}

func NewSessionStore() *SessionStore {
	return &SessionStore{keys: make(map[string][32]byte)}
}

func (s *SessionStore) Set(agentID string, key [32]byte) {
	s.mu.Lock()
	s.keys[agentID] = key
	s.mu.Unlock()
}

func (s *SessionStore) Get(agentID string) ([32]byte, bool) {
	s.mu.RLock()
	k, ok := s.keys[agentID]
	s.mu.RUnlock()
	return k, ok
}

func (s *SessionStore) Delete(agentID string) {
	s.mu.Lock()
	delete(s.keys, agentID)
	s.mu.Unlock()
}

package listeners

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// ensureTLSCerts generates a self-signed certificate if certFile/keyFile are empty.
// Returns the paths to use for ListenAndServeTLS.
func ensureTLSCerts(certFile, keyFile, listenerID string) (string, string, error) {
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err != nil {
			return "", "", fmt.Errorf("cert_file not found: %w", err)
		}
		if _, err := os.Stat(keyFile); err != nil {
			return "", "", fmt.Errorf("key_file not found: %w", err)
		}
		return certFile, keyFile, nil
	}

	// Generate self-signed cert
	tmpDir := filepath.Join(os.TempDir(), "apex-certs")
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return "", "", fmt.Errorf("create cert dir: %w", err)
	}

	certPath := filepath.Join(tmpDir, listenerID+".crt")
	keyPath := filepath.Join(tmpDir, listenerID+".key")

	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, nil
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Apex C2"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certPath, keyPath, nil
}

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/config"
)

const (
	certDir      = "certs"
	certFileName = "teamserver.crt"
	keyFileName  = "teamserver.key"
	caFileName   = "ca.crt"
)

// ensureServerCerts returns cert/key paths, generating a self-signed pair if
// none are configured. Certs are stored in ./certs/ next to the teamserver binary.
func ensureServerCerts(tlsCfg config.TLSConfig) (string, string, error) {
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		if _, err := os.Stat(tlsCfg.CertFile); err != nil {
			return "", "", fmt.Errorf("cert_file not found: %w", err)
		}
		if _, err := os.Stat(tlsCfg.KeyFile); err != nil {
			return "", "", fmt.Errorf("key_file not found: %w", err)
		}
		log.Info().
			Str("cert", tlsCfg.CertFile).
			Str("key", tlsCfg.KeyFile).
			Msg("Using provided TLS certificates")
		return tlsCfg.CertFile, tlsCfg.KeyFile, nil
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", fmt.Errorf("create cert dir: %w", err)
	}

	certPath := filepath.Join(certDir, certFileName)
	keyPath := filepath.Join(certDir, keyFileName)

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			log.Info().
				Str("cert", certPath).
				Msg("Reusing existing self-signed certificate")
			return certPath, keyPath, nil
		}
	}

	log.Info().Msg("Generating self-signed TLS certificate for teamserver API")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Apex C2 Team Server",
			Organization: []string{"Apex C2"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:    []string{"localhost", "apex-teamserver"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("create cert: %w", err)
	}

	certOut, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("write cert: %w", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	certOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	log.Info().
		Str("cert", certPath).
		Str("key", keyPath).
		Msg("Self-signed TLS certificate generated")

	return certPath, keyPath, nil
}

// buildTLSConfig creates a *tls.Config for the HTTP API server.
// When mutual_tls is enabled and a ca_file is provided, clients must present
// a certificate signed by that CA.
func buildTLSConfig(tlsCfg config.TLSConfig) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	if !tlsCfg.MutualTLS {
		return tc, nil
	}

	if tlsCfg.CAFile == "" {
		tc.ClientAuth = tls.RequireAnyClientCert
		log.Warn().Msg("mTLS enabled without CA file — accepting any client certificate")
		return tc, nil
	}

	caCert, err := os.ReadFile(tlsCfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert %s: %w", tlsCfg.CAFile, err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", tlsCfg.CAFile)
	}
	tc.ClientAuth = tls.RequireAndVerifyClientCert
	tc.ClientCAs = caPool

	log.Info().
		Str("ca", tlsCfg.CAFile).
		Msg("mTLS enabled — only clients with valid certificates can connect")

	return tc, nil
}

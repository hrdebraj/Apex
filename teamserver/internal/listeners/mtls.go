package listeners

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/agents"
	"apex/teamserver/internal/credentials"
	"apex/teamserver/internal/tasks"
)

// MTLSListener is an HTTP listener with mutual TLS authentication.
type MTLSListener struct {
	config   Config
	server   *http.Server
	checkins chan CheckIn
	agents   *agents.Manager
	tasks    *tasks.Queue
	creds    *credentials.Vault
	running  bool
	mu       sync.RWMutex
}

func NewMTLS(cfg Config, agentMgr *agents.Manager, taskQueue *tasks.Queue, credVault *credentials.Vault) *MTLSListener {
	return &MTLSListener{
		config:   cfg,
		checkins: make(chan CheckIn, 256),
		agents:   agentMgr,
		tasks:    taskQueue,
		creds:    credVault,
	}
}

func (m *MTLSListener) ID() string              { return m.config.ID }
func (m *MTLSListener) Name() string             { return m.config.Name }
func (m *MTLSListener) Protocol() Protocol       { return ProtocolMTLS }
func (m *MTLSListener) BindAddress() string      { return m.config.BindAddress }
func (m *MTLSListener) BindPort() int            { return m.config.BindPort }
func (m *MTLSListener) CheckIns() <-chan CheckIn { return m.checkins }

func (m *MTLSListener) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

func (m *MTLSListener) Start(ctx context.Context) error {
	httpListener := NewHTTP(m.config, m.agents, m.tasks, m.creds)
	mux := http.NewServeMux()
	mux.HandleFunc("/", httpListener.handleCheckIn)

	addr := fmt.Sprintf("%s:%d", m.config.BindAddress, m.config.BindPort)

	certFile := m.config.Options["cert_file"]
	keyFile := m.config.Options["key_file"]
	caFile := m.config.Options["ca_file"]

	certPath, keyPath, genErr := ensureTLSCerts(certFile, keyFile, m.config.ID)
	if genErr != nil {
		return fmt.Errorf("mtls cert setup: %w", genErr)
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("read CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.ClientCAs = caCertPool
	} else {
		tlsConfig.ClientAuth = tls.RequireAnyClientCert
	}

	m.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return context.Background() },
	}

	m.mu.Lock()
	m.running = true
	m.mu.Unlock()

	log.Info().
		Str("protocol", "mtls").
		Str("addr", addr).
		Str("name", m.config.Name).
		Msg("mTLS listener started")

	err := m.server.ListenAndServeTLS(certPath, keyPath)
	if err != nil && err != http.ErrServerClosed {
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		return fmt.Errorf("mtls serve: %w", err)
	}
	return nil
}

func (m *MTLSListener) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.server != nil {
		if err := m.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("mtls shutdown: %w", err)
		}
	}
	m.running = false
	log.Info().Str("name", m.config.Name).Msg("mTLS listener stopped")
	return nil
}

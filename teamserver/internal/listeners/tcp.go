package listeners

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// TCPListener is a raw TCP listener for internal/P2P agent communication.
// Protocol: 4-byte big-endian length prefix followed by the payload.
type TCPListener struct {
	config   Config
	listener net.Listener
	checkins chan CheckIn
	running  bool
	mu       sync.RWMutex
	conns    map[string]net.Conn
	connMu   sync.Mutex
}

func NewTCP(cfg Config) *TCPListener {
	return &TCPListener{
		config:   cfg,
		checkins: make(chan CheckIn, 256),
		conns:    make(map[string]net.Conn),
	}
}

func (t *TCPListener) ID() string              { return t.config.ID }
func (t *TCPListener) Name() string             { return t.config.Name }
func (t *TCPListener) Protocol() Protocol       { return ProtocolTCP }
func (t *TCPListener) BindAddress() string      { return t.config.BindAddress }
func (t *TCPListener) BindPort() int            { return t.config.BindPort }
func (t *TCPListener) CheckIns() <-chan CheckIn { return t.checkins }

func (t *TCPListener) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}

func (t *TCPListener) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", t.config.BindAddress, t.config.BindPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("tcp listen: %w", err)
	}

	t.listener = lis
	t.mu.Lock()
	t.running = true
	t.mu.Unlock()

	log.Info().
		Str("protocol", "tcp").
		Str("addr", addr).
		Str("name", t.config.Name).
		Msg("TCP listener started")

	go func() {
		<-ctx.Done()
		t.Stop(context.Background())
	}()

	for {
		conn, err := lis.Accept()
		if err != nil {
			t.mu.RLock()
			isRunning := t.running
			t.mu.RUnlock()
			if !isRunning {
				return nil
			}
			log.Warn().Err(err).Msg("TCP accept error")
			continue
		}

		go t.handleConn(conn)
	}
}

func (t *TCPListener) Stop(_ context.Context) error {
	t.mu.Lock()
	t.running = false
	t.mu.Unlock()

	if t.listener != nil {
		t.listener.Close()
	}

	t.connMu.Lock()
	for addr, conn := range t.conns {
		conn.Close()
		delete(t.conns, addr)
	}
	t.connMu.Unlock()

	log.Info().Str("name", t.config.Name).Msg("TCP listener stopped")
	return nil
}

func (t *TCPListener) handleConn(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	ip, _, _ := net.SplitHostPort(remote)

	t.connMu.Lock()
	t.conns[remote] = conn
	t.connMu.Unlock()

	defer func() {
		t.connMu.Lock()
		delete(t.conns, remote)
		t.connMu.Unlock()
	}()

	log.Debug().Str("remote", remote).Msg("TCP connection accepted")

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

		// Read 4-byte length prefix
		var length uint32
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			if err != io.EOF {
				log.Debug().Err(err).Str("remote", remote).Msg("TCP read length error")
			}
			return
		}

		if length > 10<<20 { // 10 MB max
			log.Warn().Uint32("length", length).Str("remote", remote).Msg("TCP payload too large")
			return
		}

		// Read payload
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			log.Debug().Err(err).Str("remote", remote).Msg("TCP read payload error")
			return
		}

		agentID := ""
		if length >= 8 {
			agentID = fmt.Sprintf("%x", payload[:8])
		}

		t.checkins <- CheckIn{
			AgentID:    agentID,
			ExternalIP: ip,
			Data:       payload,
		}

		// Send response (pending tasks will be wired here later)
		resp := []byte{0x00}
		var respLen uint32 = uint32(len(resp))
		binary.Write(conn, binary.BigEndian, respLen)
		conn.Write(resp)
	}
}

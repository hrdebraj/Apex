package agents

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

type Agent struct {
	ID          string    `json:"id"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	PID         int       `json:"pid"`
	ProcessName string    `json:"process_name"`
	InternalIP  string    `json:"internal_ip"`
	ExternalIP  string    `json:"external_ip"`
	Sleep       int       `json:"sleep"`
	Jitter      int       `json:"jitter"`
	ListenerID  string    `json:"listener_id"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Alive       bool      `json:"alive"`
}

type Manager struct {
	db     *pgxpool.Pool
	agents map[string]*Agent
	mu     sync.RWMutex
	// Channels for broadcasting agent events to connected operator clients
	eventSubs []chan AgentEvent
	subMu     sync.Mutex
}

type EventType string

const (
	EventCheckedIn    EventType = "checked_in"
	EventRegistered   EventType = "registered"
	EventDisconnected EventType = "disconnected"
	EventTaskResult   EventType = "task_result"
)

type AgentEvent struct {
	Type    EventType `json:"type"`
	AgentID string    `json:"agent_id"`
	Data    any       `json:"data,omitempty"`
}

func NewManager(db *pgxpool.Pool) *Manager {
	return &Manager{
		db:     db,
		agents: make(map[string]*Agent),
	}
}

func (m *Manager) CheckIn(agentID string) {
	m.mu.Lock()
	a, ok := m.agents[agentID]
	if ok {
		a.LastSeen = time.Now()
		a.Alive = true
	}
	m.mu.Unlock()

	if !ok {
		log.Warn().Str("agent_id", agentID).Msg("CheckIn for unknown agent ID (ignored)")
		return
	}

	m.broadcast(AgentEvent{Type: EventCheckedIn, AgentID: agentID})
}

// BroadcastTaskResult notifies subscribers of a task result (e.g. for terminal/UI).
func (m *Manager) BroadcastTaskResult(agentID string, result any) {
	m.broadcast(AgentEvent{Type: EventTaskResult, AgentID: agentID, Data: result})
}

func (m *Manager) Get(id string) (*Agent, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.agents[id]
	return a, ok
}

// FindExisting returns an agent with matching hostname, username, internalIP if seen recently.
// PID is excluded so multiple runs of the agent on the same machine (different PIDs) reuse one agent.
func (m *Manager) FindExisting(hostname, username string, pid int, internalIP string, within time.Duration) *Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cutoff := time.Now().Add(-within)
	for _, a := range m.agents {
		if a.Hostname == hostname && a.Username == username && a.InternalIP == internalIP {
			if a.LastSeen.After(cutoff) {
				return a
			}
		}
	}
	return nil
}

// RegisterOrReuse atomically finds an existing agent (hostname+username+internalIP within window)
// or registers a new one. Match excludes PID so restarts on same machine reuse the same agent.
func (m *Manager) RegisterOrReuse(ctx context.Context, agent *Agent, within time.Duration) (*Agent, bool, error) {
	m.mu.Lock()
	cutoff := time.Now().Add(-within)
	for _, a := range m.agents {
		if a.Hostname == agent.Hostname && a.Username == agent.Username && a.InternalIP == agent.InternalIP {
			if a.LastSeen.After(cutoff) {
				a.LastSeen = time.Now()
				a.Alive = true
				a.PID = agent.PID // Update to latest process
				a.ProcessName = agent.ProcessName
				a.ExternalIP = agent.ExternalIP
				m.mu.Unlock()
				return a, true, nil
			}
		}
	}

	agent.FirstSeen = time.Now()
	agent.LastSeen = time.Now()
	agent.Alive = true
	m.agents[agent.ID] = agent
	m.mu.Unlock()

	// Respond to agent immediately - broadcast so UI gets it, persist in background
	// This avoids "context canceled" when agent closes connection before DB write completes
	m.broadcast(AgentEvent{Type: EventRegistered, AgentID: agent.ID, Data: agent})

	go func() {
		dbCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		// Use NULL for listener_id: listeners are in-memory only, not in DB (avoids agents_listener_id_fkey)
		_, err := m.db.Exec(dbCtx,
			`INSERT INTO agents (id, hostname, username, os, arch, pid, process_name, internal_ip, external_ip, sleep_interval, jitter, listener_id, first_seen, last_seen)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NULL,$12,$13)
			 ON CONFLICT (id) DO UPDATE SET last_seen = $13`,
			agent.ID, agent.Hostname, agent.Username, agent.OS, agent.Arch,
			agent.PID, agent.ProcessName, agent.InternalIP, agent.ExternalIP,
			agent.Sleep, agent.Jitter, agent.FirstSeen, agent.LastSeen,
		)
		if err != nil {
			log.Error().Err(err).Str("agent_id", agent.ID).Msg("Failed to persist agent (background)")
		}
	}()
	log.Info().
		Str("id", agent.ID).
		Str("hostname", agent.Hostname).
		Str("user", agent.Username).
		Msg("Agent registered")

	return agent, false, nil
}

func (m *Manager) List() []*Agent {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		result = append(result, a)
	}
	return result
}

func (m *Manager) Remove(ctx context.Context, id string) error {
	m.mu.Lock()
	delete(m.agents, id)
	m.mu.Unlock()

	_, err := m.db.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id)
	return err
}

func (m *Manager) Subscribe() <-chan AgentEvent {
	ch := make(chan AgentEvent, 64)
	m.subMu.Lock()
	m.eventSubs = append(m.eventSubs, ch)
	m.subMu.Unlock()
	return ch
}

func (m *Manager) broadcast(event AgentEvent) {
	m.subMu.Lock()
	defer m.subMu.Unlock()

	for _, ch := range m.eventSubs {
		select {
		case ch <- event:
		default:
		}
	}
}

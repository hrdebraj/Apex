package listeners

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/agents"
	"apex/teamserver/internal/tasks"
)

type Manager struct {
	listeners map[string]Listener
	agents    *agents.Manager
	tasks     *tasks.Queue
	mu        sync.RWMutex
}

func NewManager(agentMgr *agents.Manager, taskQueue *tasks.Queue) *Manager {
	return &Manager{
		listeners: make(map[string]Listener),
		agents:    agentMgr,
		tasks:     taskQueue,
	}
}

func (m *Manager) Create(cfg Config) (Listener, error) {
	if cfg.ID == "" {
		cfg.ID = uuid.New().String()
	}

	var l Listener
	switch cfg.Protocol {
	case ProtocolHTTP, ProtocolHTTPS:
		l = NewHTTP(cfg, m.agents, m.tasks)
	case ProtocolMTLS:
		l = NewMTLS(cfg, m.agents, m.tasks)
	case ProtocolDNS:
		l = NewDNS(cfg)
	case ProtocolTCP:
		l = NewTCP(cfg)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cfg.Protocol)
	}

	m.mu.Lock()
	m.listeners[cfg.ID] = l
	m.mu.Unlock()

	log.Info().Str("id", cfg.ID).Str("name", cfg.Name).Str("protocol", string(cfg.Protocol)).Msg("Listener created")
	return l, nil
}

func (m *Manager) Start(ctx context.Context, id string) error {
	m.mu.RLock()
	l, ok := m.listeners[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}

	go func() {
		if err := l.Start(ctx); err != nil {
			log.Error().Err(err).Str("id", id).Msg("Listener failed")
		}
	}()

	return nil
}

func (m *Manager) Stop(ctx context.Context, id string) error {
	m.mu.RLock()
	l, ok := m.listeners[id]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}
	return l.Stop(ctx)
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	l, ok := m.listeners[id]
	if !ok {
		return fmt.Errorf("listener not found: %s", id)
	}

	if l.IsRunning() {
		if err := l.Stop(ctx); err != nil {
			return err
		}
	}

	delete(m.listeners, id)
	return nil
}

func (m *Manager) Get(id string) (Listener, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.listeners[id]
	return l, ok
}

func (m *Manager) List() []Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		result = append(result, l)
	}
	return result
}

func (m *Manager) StopAll(ctx context.Context) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for id, l := range m.listeners {
		if l.IsRunning() {
			if err := l.Stop(ctx); err != nil {
				log.Error().Err(err).Str("id", id).Msg("Failed to stop listener")
			}
		}
	}
}

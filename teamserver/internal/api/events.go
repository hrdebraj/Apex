package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/rs/zerolog/log"
)

// EventHub provides Server-Sent Events (SSE) to connected operator clients.
// All real-time updates (agent check-ins, task results, listener changes)
// are pushed through here.
type EventHub struct {
	clients map[chan Event]struct{}
	mu      sync.RWMutex
}

type Event struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

func NewEventHub() *EventHub {
	return &EventHub{
		clients: make(map[chan Event]struct{}),
	}
}

func (h *EventHub) Broadcast(eventType string, data any) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	event := Event{Type: eventType, Data: data}
	for ch := range h.clients {
		select {
		case ch <- event:
		default:
			// Slow client, drop event
		}
	}
}

func (h *EventHub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	ch := make(chan Event, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
		close(ch)
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	// Send initial ping
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	log.Debug().Msg("SSE client connected")

	for {
		select {
		case <-r.Context().Done():
			log.Debug().Msg("SSE client disconnected")
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}

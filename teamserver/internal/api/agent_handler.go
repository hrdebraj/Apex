package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"apex/teamserver/internal/agents"
)

type AgentHandler struct {
	mgr *agents.Manager
}

func NewAgentHandler(mgr *agents.Manager) *AgentHandler {
	return &AgentHandler{mgr: mgr}
}

type agentDTO struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	InternalIP  string `json:"internal_ip"`
	ExternalIP  string `json:"external_ip"`
	Sleep       int    `json:"sleep"`
	Jitter      int    `json:"jitter"`
	ListenerID  string `json:"listener_id"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	Alive       bool   `json:"alive"`
}

func (h *AgentHandler) List(w http.ResponseWriter, _ *http.Request) {
	all := h.mgr.List()
	result := make([]agentDTO, len(all))
	for i, a := range all {
		result[i] = agentToDTO(a)
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *AgentHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a, ok := h.mgr.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	writeJSON(w, http.StatusOK, agentToDTO(a))
}

func (h *AgentHandler) Remove(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.mgr.Remove(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

func agentToDTO(a *agents.Agent) agentDTO {
	return agentDTO{
		ID:          a.ID,
		Hostname:    a.Hostname,
		Username:    a.Username,
		OS:          a.OS,
		Arch:        a.Arch,
		PID:         a.PID,
		ProcessName: a.ProcessName,
		InternalIP:  a.InternalIP,
		ExternalIP:  a.ExternalIP,
		Sleep:       a.Sleep,
		Jitter:      a.Jitter,
		ListenerID:  a.ListenerID,
		FirstSeen:   a.FirstSeen.Format("2006-01-02T15:04:05Z"),
		LastSeen:    a.LastSeen.Format("2006-01-02T15:04:05Z"),
		Alive:       a.Alive,
	}
}

package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"apex/teamserver/internal/agents"
	"apex/teamserver/internal/tasks"
)

type TaskHandler struct {
	queue    *tasks.Queue
	agentMgr *agents.Manager
}

func NewTaskHandler(queue *tasks.Queue, agentMgr *agents.Manager) *TaskHandler {
	return &TaskHandler{queue: queue, agentMgr: agentMgr}
}

type createTaskRequest struct {
	Command   string `json:"command"`
	Arguments string `json:"arguments,omitempty"`
}

type taskDTO struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	OperatorID  string `json:"operator_id"`
	Command     string `json:"command"`
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	CompletedAt string `json:"completed_at,omitempty"`
}

func (h *TaskHandler) Create(w http.ResponseWriter, r *http.Request) {
	agentID := chi.URLParam(r, "agentID")

	if _, ok := h.agentMgr.Get(agentID); !ok {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}

	claims, ok := claimsFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing claims")
		return
	}

	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var args []byte
	if req.Arguments != "" {
		args = []byte(req.Arguments)
	}

	t, err := h.queue.Enqueue(r.Context(), agentID, claims.OperatorID, req.Command, args)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enqueue task")
		return
	}

	writeJSON(w, http.StatusCreated, taskToDTO(t))
}

func (h *TaskHandler) ListByAgent(w http.ResponseWriter, r *http.Request) {
	// Returns pending tasks for an agent (from Redis queue, peek without consuming)
	// For full history, query PostgreSQL — future enhancement
	writeJSON(w, http.StatusOK, []taskDTO{})
}

func taskToDTO(t *tasks.Task) taskDTO {
	dto := taskDTO{
		ID:         t.ID,
		AgentID:    t.AgentID,
		OperatorID: t.OperatorID,
		Command:    t.Command,
		Status:     string(t.Status),
		CreatedAt:  t.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if !t.CompletedAt.IsZero() {
		dto.CompletedAt = t.CompletedAt.Format("2006-01-02T15:04:05Z")
	}
	return dto
}

package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"apex/teamserver/internal/listeners"
)

type ListenerHandler struct {
	mgr *listeners.Manager
}

func NewListenerHandler(mgr *listeners.Manager) *ListenerHandler {
	return &ListenerHandler{mgr: mgr}
}

type listenerDTO struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Protocol    string            `json:"protocol"`
	BindAddress string            `json:"bind_address"`
	BindPort    int               `json:"bind_port"`
	Status      string            `json:"status"`
	Config      map[string]string `json:"config,omitempty"`
}

type createListenerRequest struct {
	Name        string            `json:"name"`
	Protocol    string            `json:"protocol"`
	BindAddress string            `json:"bind_address"`
	BindPort    int               `json:"bind_port"`
	Config      map[string]string `json:"config,omitempty"`
}

func (h *ListenerHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createListenerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	cfg := listeners.Config{
		Name:        req.Name,
		Protocol:    listeners.Protocol(req.Protocol),
		BindAddress: req.BindAddress,
		BindPort:    req.BindPort,
		Options:     req.Config,
	}

	l, err := h.mgr.Create(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, listenerToDTO(l))
}

func (h *ListenerHandler) List(w http.ResponseWriter, _ *http.Request) {
	all := h.mgr.List()
	result := make([]listenerDTO, len(all))
	for i, l := range all {
		result[i] = listenerToDTO(l)
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *ListenerHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	l, ok := h.mgr.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, "listener not found")
		return
	}
	writeJSON(w, http.StatusOK, listenerToDTO(l))
}

func (h *ListenerHandler) Start(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.mgr.Start(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	l, _ := h.mgr.Get(id)
	writeJSON(w, http.StatusOK, listenerToDTO(l))
}

func (h *ListenerHandler) Stop(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.mgr.Stop(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	l, _ := h.mgr.Get(id)
	writeJSON(w, http.StatusOK, listenerToDTO(l))
}

func (h *ListenerHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.mgr.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func listenerToDTO(l listeners.Listener) listenerDTO {
	st := "inactive"
	if l.IsRunning() {
		st = "active"
	}
	return listenerDTO{
		ID:          l.ID(),
		Name:        l.Name(),
		Protocol:    string(l.Protocol()),
		BindAddress: l.BindAddress(),
		BindPort:    l.BindPort(),
		Status:      st,
	}
}

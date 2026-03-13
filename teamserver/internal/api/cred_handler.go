package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"apex/teamserver/internal/credentials"
)

type CredentialHandler struct {
	vault *credentials.Vault
}

func NewCredentialHandler(v *credentials.Vault) *CredentialHandler {
	return &CredentialHandler{vault: v}
}

func (h *CredentialHandler) List(w http.ResponseWriter, r *http.Request) {
	creds, err := h.vault.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(creds)
}

type addCredentialRequest struct {
	AgentID  string `json:"agent_id,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
	Type     string `json:"type"`
	Source   string `json:"source,omitempty"`
}

func (h *CredentialHandler) Add(w http.ResponseWriter, r *http.Request) {
	var req addCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Username == "" || req.Secret == "" {
		writeError(w, http.StatusBadRequest, "username and secret required")
		return
	}
	if req.Type == "" {
		req.Type = "plaintext"
	}

	cred := &credentials.Credential{
		AgentID:  req.AgentID,
		Domain:   req.Domain,
		Username: req.Username,
		Secret:   req.Secret,
		Type:     req.Type,
		Source:   req.Source,
	}

	if err := h.vault.Add(r.Context(), cred); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cred)
}

func (h *CredentialHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.vault.Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

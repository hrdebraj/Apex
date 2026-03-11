package api

import (
	"encoding/json"
	"net/http"

	"apex/teamserver/internal/auth"
)

type AuthHandler struct {
	svc *auth.Service
}

func NewAuthHandler(svc *auth.Service) *AuthHandler {
	return &AuthHandler{svc: svc}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token    string        `json:"token"`
	Operator *operatorDTO  `json:"operator"`
}

type operatorDTO struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type createOperatorRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, op, err := h.svc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	writeJSON(w, http.StatusOK, loginResponse{
		Token: token,
		Operator: &operatorDTO{
			ID:       op.ID,
			Username: op.Username,
			Role:     string(op.Role),
		},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromRequest(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing claims")
		return
	}

	writeJSON(w, http.StatusOK, operatorDTO{
		ID:       claims.OperatorID,
		Username: claims.Username,
		Role:     string(claims.Role),
	})
}

func (h *AuthHandler) CreateOperator(w http.ResponseWriter, r *http.Request) {
	claims, ok := claimsFromRequest(r)
	if !ok || claims.Role != auth.RoleAdmin {
		writeError(w, http.StatusForbidden, "admin only")
		return
	}

	var req createOperatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	role := auth.Role(req.Role)
	if role != auth.RoleAdmin && role != auth.RoleOperator && role != auth.RoleReadOnly {
		role = auth.RoleOperator
	}

	op, err := h.svc.CreateOperator(r.Context(), req.Username, req.Password, role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create operator")
		return
	}

	writeJSON(w, http.StatusCreated, operatorDTO{
		ID:       op.ID,
		Username: op.Username,
		Role:     string(op.Role),
	})
}

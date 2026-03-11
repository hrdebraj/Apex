package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"apex/teamserver/internal/auth"
)

type ctxKey string

const claimsCtxKey ctxKey = "claims"

func JWTMiddleware(authSvc *auth.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("token")
			if token == "" {
				header := r.Header.Get("Authorization")
				token = strings.TrimPrefix(header, "Bearer ")
			}
			if token == "" {
				writeError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}
			claims, err := authSvc.ValidateToken(token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func claimsFromRequest(r *http.Request) (*auth.Claims, bool) {
	c, ok := r.Context().Value(claimsCtxKey).(*auth.Claims)
	return c, ok
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

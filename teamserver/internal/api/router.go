package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"

	"apex/teamserver/internal/agents"
	"apex/teamserver/internal/auth"
	"apex/teamserver/internal/credentials"
	"apex/teamserver/internal/listeners"
	"apex/teamserver/internal/tasks"
)

type API struct {
	Auth       *auth.Service
	Agents     *agents.Manager
	Listeners  *listeners.Manager
	Tasks      *tasks.Queue
	Creds      *credentials.Vault
	DB         *pgxpool.Pool
	EventHub   *EventHub
	ProfileDir string
	AgentDir   string // path to agent source (empty = auto-detect)
}

func NewRouter(a *API) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:1420", "https://localhost:1420", "tauri://localhost"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	authHandler := NewAuthHandler(a.Auth)
	listenerHandler := NewListenerHandler(a.Listeners)
	agentHandler := NewAgentHandler(a.Agents)
	taskHandler := NewTaskHandler(a.Tasks, a.Agents)
	credHandler := NewCredentialHandler(a.Creds)
	profileHandler := NewProfileHandler(a.ProfileDir)
	payloadHandler := NewPayloadHandler(a.Listeners, a.AgentDir)

	r.Route("/api", func(r chi.Router) {
		// Public
		r.Post("/auth/login", authHandler.Login)

		// Protected
		r.Group(func(r chi.Router) {
			r.Use(JWTMiddleware(a.Auth))

			r.Post("/auth/logout", authHandler.Logout)
			r.Get("/auth/me", authHandler.Me)
			r.Post("/operators", authHandler.CreateOperator)

			r.Get("/listeners", listenerHandler.List)
			r.Post("/listeners", listenerHandler.Create)
			r.Get("/listeners/{id}", listenerHandler.Get)
			r.Post("/listeners/{id}/start", listenerHandler.Start)
			r.Post("/listeners/{id}/stop", listenerHandler.Stop)
			r.Delete("/listeners/{id}", listenerHandler.Delete)

			r.Get("/agents", agentHandler.List)
			r.Get("/agents/{id}", agentHandler.Get)
			r.Delete("/agents/{id}", agentHandler.Remove)

			r.Post("/agents/{agentID}/tasks", taskHandler.Create)
			r.Get("/agents/{agentID}/tasks", taskHandler.ListByAgent)

			r.Get("/credentials", credHandler.List)
			r.Post("/credentials", credHandler.Add)
			r.Delete("/credentials/{id}", credHandler.Delete)

			r.Get("/profiles", profileHandler.List)
			r.Post("/profiles", profileHandler.Upload)
			r.Get("/profiles/{name}", profileHandler.Get)
			r.Delete("/profiles/{name}", profileHandler.Delete)

			r.Post("/payloads/generate", payloadHandler.Generate)
			r.Get("/payloads/bofs", payloadHandler.ListBOFs)
			r.Post("/payloads/bofs", payloadHandler.UploadBOF)
			r.Delete("/payloads/bofs", payloadHandler.DeleteBOF)

			r.Get("/events", a.EventHub.ServeSSE)
		})
	})

	return r
}

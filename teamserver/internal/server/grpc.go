package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"apex/teamserver/internal/agents"
	"apex/teamserver/internal/api"
	"apex/teamserver/internal/auth"
	"apex/teamserver/internal/config"
	"apex/teamserver/internal/credentials"
	grpcsvc "apex/teamserver/internal/grpc"
	"apex/teamserver/internal/listeners"
	"apex/teamserver/internal/tasks"
	pb "apex/teamserver/pkg/proto/apexpb"
)

type Server struct {
	cfg      *config.Config
	grpc     *grpc.Server
	http     *http.Server
	listener net.Listener

	tlsCert string
	tlsKey  string

	Auth      *auth.Service
	Agents    *agents.Manager
	Listeners *listeners.Manager
	Tasks     *tasks.Queue
	EventHub  *api.EventHub
	DB        *pgxpool.Pool
}

func New(cfg *config.Config, db *pgxpool.Pool, rdb *redis.Client) (*Server, error) {
	authSvc := auth.NewService(db, cfg.Auth)
	agentMgr := agents.NewManager(db)
	taskQueue := tasks.NewQueue(rdb)
	credVault := credentials.NewVault(db)
	listenerMgr := listeners.NewManager(agentMgr, taskQueue, credVault)
	eventHub := api.NewEventHub()

	// gRPC server with auth interceptors
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(grpcsvc.AuthUnaryInterceptor(authSvc)),
		grpc.ChainStreamInterceptor(grpcsvc.AuthStreamInterceptor(authSvc)),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute,
			Time:              2 * time.Minute,
			Timeout:           20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	grpcServer := grpc.NewServer(opts...)
	reflection.Register(grpcServer)

	// Register gRPC service handlers
	pb.RegisterAuthServiceServer(grpcServer, grpcsvc.NewAuthServiceServer(authSvc))
	pb.RegisterListenerServiceServer(grpcServer, grpcsvc.NewListenerServiceServer(listenerMgr))
	pb.RegisterAgentServiceServer(grpcServer, grpcsvc.NewAgentServiceServer(agentMgr))
	pb.RegisterTaskServiceServer(grpcServer, grpcsvc.NewTaskServiceServer(taskQueue))

	// REST API (HTTP) server
	router := api.NewRouter(&api.API{
		Auth:       authSvc,
		Agents:     agentMgr,
		Listeners:  listenerMgr,
		Tasks:      taskQueue,
		Creds:      credVault,
		DB:         db,
		EventHub:   eventHub,
		ProfileDir: "profiles",
		AgentDir:   cfg.Server.AgentDir,
	})

	httpServer := &http.Server{
		Addr:         cfg.Server.HTTPAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE needs no write timeout
		IdleTimeout:  120 * time.Second,
	}

	var certPath, keyPath string
	if cfg.Server.TLS.Enabled {
		var err error
		certPath, keyPath, err = ensureServerCerts(cfg.Server.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls setup: %w", err)
		}

		tlsConfig, err := buildTLSConfig(cfg.Server.TLS)
		if err != nil {
			return nil, fmt.Errorf("tls config: %w", err)
		}
		httpServer.TLSConfig = tlsConfig
	}

	srv := &Server{
		cfg:       cfg,
		grpc:      grpcServer,
		http:      httpServer,
		tlsCert:   certPath,
		tlsKey:    keyPath,
		Auth:      authSvc,
		Agents:    agentMgr,
		Listeners: listenerMgr,
		Tasks:     taskQueue,
		EventHub:  eventHub,
		DB:        db,
	}

	// Wire agent events to SSE hub
	go srv.forwardAgentEvents()

	return srv, nil
}

func (s *Server) StartGRPC() error {
	lis, err := net.Listen("tcp", s.cfg.Server.GRPCAddr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", s.cfg.Server.GRPCAddr, err)
	}
	s.listener = lis
	log.Info().Str("addr", s.cfg.Server.GRPCAddr).Msg("gRPC server listening")
	return s.grpc.Serve(lis)
}

func (s *Server) StartHTTP() error {
	if s.tlsCert != "" && s.tlsKey != "" {
		proto := "HTTPS"
		if s.cfg.Server.TLS.MutualTLS {
			proto = "HTTPS+mTLS"
		}
		log.Info().
			Str("addr", s.cfg.Server.HTTPAddr).
			Str("proto", proto).
			Msg("API server listening")
		err := s.http.ListenAndServeTLS(s.tlsCert, s.tlsKey)
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("https listen: %w", err)
		}
		return nil
	}

	log.Warn().
		Str("addr", s.cfg.Server.HTTPAddr).
		Msg("API server listening (plaintext HTTP — set tls.enabled=true in config)")
	err := s.http.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("http listen: %w", err)
	}
	return nil
}

func (s *Server) Stop() {
	log.Info().Msg("Stopping servers (graceful)")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s.http.Shutdown(ctx)
	s.grpc.GracefulStop()
	s.Listeners.StopAll(ctx)
}

func (s *Server) forwardAgentEvents() {
	ch := s.Agents.Subscribe()
	for event := range ch {
		s.EventHub.Broadcast("agent:"+string(event.Type), event)
	}
}

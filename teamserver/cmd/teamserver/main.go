package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/config"
	"apex/teamserver/internal/db"
	"apex/teamserver/internal/server"
)

const banner = `
   ___    ____  _______  __
  / _ |  / __ \/ __/ _ \/ /
 / __ | / /_/ / _// ___/\ \ 
/_/ |_|/ .___/___/_/  /___/ 
      /_/  Team Server v0.1.0
`

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	os.Stdout.WriteString(banner + "\n")

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	level, err := zerolog.ParseLevel(cfg.Logging.Level)
	if err == nil {
		zerolog.SetGlobalLevel(level)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pgPool, err := db.NewPostgres(ctx, cfg.Database.Postgres)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to PostgreSQL")
	}
	defer pgPool.Close()

	rdb, err := db.NewRedis(ctx, cfg.Database.Redis)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to Redis")
	}
	defer rdb.Close()

	srv, err := server.New(cfg, pgPool, rdb)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}

	go func() {
		if err := srv.StartGRPC(); err != nil {
			log.Fatal().Err(err).Msg("gRPC server failed")
		}
	}()

	go func() {
		if err := srv.StartHTTP(); err != nil {
			log.Fatal().Err(err).Msg("HTTP API server failed")
		}
	}()

	log.Info().
		Str("grpc", cfg.Server.GRPCAddr).
		Str("http", cfg.Server.HTTPAddr).
		Msg("Apex Team Server is online")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	log.Info().Str("signal", sig.String()).Msg("Shutting down")
	srv.Stop()
	cancel()
}

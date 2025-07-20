package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/thegenem0/atlas/internal/config"
	"github.com/thegenem0/atlas/internal/logging"
	"github.com/thegenem0/atlas/internal/server"
)

const version = "0.0.1"

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	logging.Setup(cfg.Logging.Level, cfg.Logging.Pretty)

	log.Info().
		Str("version", version).
		Str("host", cfg.Server.Host).
		Int("port", cfg.Server.Port).
		Msg("Starting Atlas Identity Server")

	srv, err := server.New(cfg, version)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}

	// Start server
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
		log.Info().Str("address", addr).Msg("Server starting")

		if err := srv.Start(addr); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("Server failed to start")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Server shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exited")
}

package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"github.com/thegenem0/atlas/internal/config"
	"github.com/thegenem0/atlas/internal/database"
	"github.com/thegenem0/atlas/internal/health"
)

type Server struct {
	httpServer *http.Server
	config     *config.Config
	db         *database.DB
}

func New(cfg *config.Config, version string) (*Server, error) {
	db, err := database.New(&cfg.Database)
	if err != nil {
		return nil, err
	}

	migrator, err := database.NewDistributedMigrator(db, "migrations")
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create migrator")
	} else {

		if err := migrator.CleanupStaleMigrations(); err != nil {
			log.Warn().Err(err).Msg("Failed to cleanup stale migrations")
		}

		if err := migrator.Up(); err != nil {
			log.Error().Err(err).Msg("Failed to run migrations")
			return nil, err
		}

		migrator.Close()
	}

	router := mux.NewRouter()

	healthHandler := health.NewHandler(version)
	healthHandler.AddChecker(database.NewHealthChecker(db))

	router.Handle("/health", healthHandler).Methods("GET")
	router.HandleFunc("/health/live", health.LivenessHandler(version)).Methods("GET")

	httpServer := &http.Server{
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	return &Server{
		httpServer: httpServer,
		config:     cfg,
	}, nil
}

func (s *Server) Start(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down server")

	if s.db != nil {
		s.db.Close()
	}

	return s.httpServer.Shutdown(ctx)
}

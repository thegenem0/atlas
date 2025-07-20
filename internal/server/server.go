package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/thegenem0/atlas/internal/config"
	"github.com/thegenem0/atlas/internal/health"
)

type Server struct {
	httpServer *http.Server
	config     *config.Config
}

func New(cfg *config.Config, version string) (*Server, error) {

	router := mux.NewRouter()

	healthHandler := health.NewHandler(version)
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
	return s.httpServer.Shutdown(ctx)
}

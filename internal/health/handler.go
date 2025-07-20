package health

import (
	"encoding/json"
	"net/http"
	"time"
)

type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusUnhealthy Status = "unhealthy"
	StatusDegraded  Status = "degraded"
)

type CheckResult struct {
	Status Status `json:"status"`
	Error  string `json:"error,omitempty"`
}

type Response struct {
	Status    Status                 `json:"status"`
	Timestamp time.Time              `json:"timestamp"`
	Version   string                 `json:"version"`
	Checks    map[string]CheckResult `json:"checks"`
}

type Checker interface {
	Name() string
	Check() CheckResult
}

type Handler struct {
	version  string
	checkers []Checker
}

func NewHandler(version string) *Handler {
	return &Handler{
		version:  version,
		checkers: make([]Checker, 0),
	}
}

func (h *Handler) AddChecker(checker Checker) {
	h.checkers = append(h.checkers, checker)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]CheckResult)
	overallStatus := StatusHealthy

	for _, checker := range h.checkers {
		result := checker.Check()
		checks[checker.Name()] = result

		if result.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if result.Status == StatusDegraded && overallStatus == StatusHealthy {
			overallStatus = StatusDegraded
		}
	}

	response := Response{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Version:   h.version,
		Checks:    checks,
	}

	statusCode := http.StatusOK
	switch overallStatus {
	case StatusUnhealthy:
		statusCode = http.StatusServiceUnavailable
	case StatusDegraded:
		statusCode = http.StatusPartialContent
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

func LivenessHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		response := map[string]any{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   version,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

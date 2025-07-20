package database

import (
	"context"
	"time"

	"github.com/thegenem0/atlas/internal/health"
)

// HealthChecker implements `health.Checker`
type HealthChecker struct {
	db *DB
}

func NewHealthChecker(db *DB) *HealthChecker {
	return &HealthChecker{
		db: db,
	}
}

func (h *HealthChecker) Name() string {
	return "database"
}

func (h *HealthChecker) Check() health.CheckResult {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := h.db.Ping(ctx); err != nil {
		return health.CheckResult{
			Status: health.StatusUnhealthy,
			Error:  err.Error(),
		}
	}

	stats := h.db.Stats()
	if stats.OpenConnections >= stats.MaxOpenConnections {
		return health.CheckResult{
			Status: health.StatusDegraded,
			Error:  "connection pool exhausted",
		}
	}

	return health.CheckResult{
		Status: health.StatusHealthy,
	}
}

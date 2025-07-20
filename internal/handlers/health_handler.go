package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/thegenem0/atlas/internal/database"
)

type HealthHandler struct {
	db database.IDatabase
}

func NewHealthHandler(db database.IDatabase) *HealthHandler {
	return &HealthHandler{db: db}
}

func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {

	health := map[string]any{
		"database":  "unknown",
		"migration": "unknown",
	}

	if err := h.db.Ping(); err != nil {
		health["database"] = "degraded"
		health["database_error"] = err.Error()
	} else {
		health["database"] = "operational"
	}

	if version, dirty, err := h.db.GetMigrationVersion(); err != nil {
		health["migration"] = "error"
		health["migration_error"] = err.Error()
	} else {
		health["migration"] = "operational"
		health["migration_version"] = version
		health["migration_dirty"] = dirty
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}

package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/thegenem0/atlas/internal/database"
)

type contextKey string

const (
	TenantContextKey contextKey = "tenant"
	UserContextKey   contextKey = "user"
)

type TenantMiddleware struct {
	db database.IQueryStore
}

func NewTenantMiddleware(db database.IQueryStore) *TenantMiddleware {
	return &TenantMiddleware{db: db}
}

func (m *TenantMiddleware) Extract(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract tenant from URL path: /tenants/{tenant-name}/...
		pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")

		if len(pathParts) < 2 || pathParts[0] != "tenants" {
			http.Error(w, "Invalid tenant path", http.StatusBadRequest)
			return
		}

		tenantName := pathParts[1]

		// Get tenant from database
		tenant, err := m.db.GetTenantByName(r.Context(), tenantName)
		if err != nil {
			if err == database.ErrTenantNotFound {
				http.Error(w, "Tenant not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !tenant.Enabled {
			http.Error(w, "Tenant disabled", http.StatusForbidden)
			return
		}

		// Add tenant to request context
		ctx := context.WithValue(r.Context(), TenantContextKey, tenant)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

package router

import (
	"github.com/gorilla/mux"
	"github.com/thegenem0/atlas/internal/database"
	"github.com/thegenem0/atlas/internal/handlers"
	"github.com/thegenem0/atlas/internal/middleware"
	"github.com/thegenem0/atlas/internal/services"
)

func NewRouter(
	db database.IDatabase,
	authService *services.AuthService,
	tenantMiddleware *middleware.TenantMiddleware,
	authMiddleware *middleware.AuthMiddleware,
) *mux.Router {
	r := mux.NewRouter()

	healthHandler := handlers.NewHealthHandler(db)

	// Health check
	r.HandleFunc("/health", healthHandler.Health).Methods("GET")

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService)

	// Tenant-scoped routes
	tenantRouter := r.PathPrefix("/tenants/{tenant}").Subrouter()
	tenantRouter.Use(tenantMiddleware.Extract)

	// Authentication endpoints (no auth required)
	authRouter := tenantRouter.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/login", authHandler.Login).Methods("POST")
	authRouter.HandleFunc("/refresh", authHandler.Refresh).Methods("POST")
	authRouter.HandleFunc("/logout", authHandler.Logout).Methods("POST")

	// Protected admin endpoints
	adminRouter := tenantRouter.PathPrefix("/admin").Subrouter()
	adminRouter.Use(authMiddleware.RequireAuth)

	return r
}

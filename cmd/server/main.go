package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/rs/zerolog"
	"github.com/thegenem0/atlas/internal/config"
	"github.com/thegenem0/atlas/internal/database"
	"github.com/thegenem0/atlas/internal/middleware"
	"github.com/thegenem0/atlas/internal/router"
	"github.com/thegenem0/atlas/internal/services"
)

func main() {
	// ctx := context.Background()

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger().Level(zerolog.InfoLevel)

	config, err := config.LoadConfig()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Configuration
	jwtSecret := getEnv("JWT_SECRET", "your-secret-key-change-this-in-production")
	port := config.Server.Port

	// Database connection
	db, err := database.NewDatabase(&config.Db, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize database")
	}
	defer db.Close()

	// Initialize services
	authService := services.NewAuthService(db, []byte(jwtSecret))

	// Initialize middleware
	tenantMiddleware := middleware.NewTenantMiddleware(db)
	authMiddleware := middleware.NewAuthMiddleware(authService)

	// Setup router
	r := router.NewRouter(db, authService, tenantMiddleware, authMiddleware)

	logger.Info().Int("port", port).Msg("Server starting")
	logger.Fatal().Err(http.ListenAndServe(":"+fmt.Sprintf("%d", port), r)).Msg("Server stopped")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

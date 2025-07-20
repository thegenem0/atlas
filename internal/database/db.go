package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/thegenem0/atlas/internal/config"
)

const (
	defaultConnectTimeout     = 30 * time.Second
	defaultMigrationTimeout   = 10 * time.Minute
	defaultHealthCheckTimeout = 5 * time.Second
	defaultRetryAttempts      = 3
	defaultRetryDelay         = 2 * time.Second
	migrationLockID           = int64(123456789)
)

type database struct {
	ICommandStore
	IQueryStore
	db        *sqlx.DB
	config    *config.DbConfig
	mu        sync.RWMutex
	healthy   bool
	logger    zerolog.Logger
	startTime time.Time
}

type MigrationStatus struct {
	Version     uint      `json:"version"`
	Dirty       bool      `json:"dirty"`
	Applied     bool      `json:"applied"`
	Error       string    `json:"error,omitempty"`
	LastApplied time.Time `json:"last_applied"`
}

type HealthStatus struct {
	Database  string          `json:"database"`
	Migration MigrationStatus `json:"migration"`
	Uptime    time.Duration   `json:"uptime"`
	Error     string          `json:"error,omitempty"`
}

func NewDatabase(config *config.DbConfig, logger zerolog.Logger) (IDatabase, error) {
	if config == nil {
		return nil, fmt.Errorf("database config cannot be nil")
	}

	dbLogger := logger.With().
		Str("component", "database").
		Str("host", config.Host).
		Int("port", config.Port).
		Str("database", config.Database).
		Logger()

	if err := validateConfig(config); err != nil {
		dbLogger.Error().Err(err).Msg("Invalid database configuration")
		return nil, fmt.Errorf("invalid database configuration: %w", err)
	}

	db, err := createDbConnection(config, &logger)
	if err != nil {
		dbLogger.Error().Err(err).Msg("Failed to create database connection")
		return nil, fmt.Errorf("failed to create database connection: %w", err)
	}

	database := &database{
		ICommandStore: NewCommandStore(db, config.Driver),
		IQueryStore:   NewQueryStore(db, config.Driver),
		db:            db,
		config:        config,
		healthy:       true,
		logger:        dbLogger,
		startTime:     time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultMigrationTimeout)
	defer cancel()

	if err := database.runMigrations(ctx); err != nil {
		dbLogger.Error().Err(err).Msg("Failed to run migrations")
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := database.verifyHealth(); err != nil {
		dbLogger.Error().Err(err).Msg("Database health check failed")
		database.Close()
		return nil, fmt.Errorf("database health check failed: %w", err)
	}

	dbLogger.Info().Msg("Database initialized successfully")
	return database, nil
}

func (d *database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.healthy = false
	if d.db != nil {
		d.logger.Info().Msg("Closing database connection")
		return d.db.Close()
	}
	return nil
}

func (d *database) Ping() error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	return d.db.Ping()
}

func (d *database) GetMigrationVersion() (uint, bool, error) {
	if d.config.MigrationPath == "" {
		return 0, false, nil
	}

	d.logger.Debug().Msg("Getting migration version")

	migrationDB, err := d.createMigrationConnection()
	if err != nil {
		d.logger.Error().Err(err).Msg("Failed to create migration connection for version check")
		return 0, false, fmt.Errorf("failed to create migration connection: %w", err)
	}
	defer migrationDB.Close()

	m, err := d.createMigrateInstance(migrationDB)
	if err != nil {
		d.logger.Error().Err(err).Msg("Failed to create migrate instance for version check")
		return 0, false, fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer m.Close()

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		d.logger.Error().Err(err).Msg("Failed to get migration version")
		return 0, false, fmt.Errorf("failed to get migration version: %w", err)
	}

	if err == migrate.ErrNilVersion {
		d.logger.Debug().Msg("No migrations have been applied yet")
		return 0, false, nil
	}

	d.logger.Debug().
		Uint("version", version).
		Bool("dirty", dirty).
		Msg("Got migration version")

	return version, dirty, nil
}

func (d *database) WaitForMigrationCompletion(timeout time.Duration) error {
	d.logger.Debug().
		Dur("timeout", timeout).
		Msg("Waiting for migration completion")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			d.logger.Error().
				Dur("timeout", timeout).
				Msg("Migration timeout exceeded")
			return fmt.Errorf("migration timeout exceeded after %s", timeout)
		case <-ticker.C:
			_, dirty, err := d.GetMigrationVersion()
			if err != nil {
				d.logger.Error().Err(err).Msg("Failed to check migration status")
				return fmt.Errorf("failed to check migration status: %w", err)
			}
			if !dirty {
				d.logger.Info().Msg("Migrations completed successfully")
				return nil
			}
			d.logger.Debug().Msg("Migrations still in progress")
		}
	}
}

func (d *database) GetHealthStatus() HealthStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	status := HealthStatus{
		Database: "unknown",
		Migration: MigrationStatus{
			Applied: false,
		},
	}

	if err := d.Ping(); err != nil {
		status.Database = "degraded"
		status.Error = err.Error()
		d.logger.Error().Err(err).Msg("Database health check failed")
	} else {
		status.Database = "operational"
	}

	if version, dirty, err := d.GetMigrationVersion(); err != nil {
		status.Migration.Error = err.Error()
		d.logger.Error().Err(err).Msg("Migration health check failed")
	} else {
		status.Migration.Version = version
		status.Migration.Dirty = dirty
		status.Migration.Applied = version > 0
		status.Migration.LastApplied = time.Now() // This would ideally come from migration table
	}

	d.logger.Debug().
		Str("database_status", status.Database).
		Uint("migration_version", status.Migration.Version).
		Bool("migration_dirty", status.Migration.Dirty).
		Dur("uptime", status.Uptime).
		Msg("Health status checked")

	return status
}

func validateConfig(config *config.DbConfig) error {
	if config.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if config.Port == 0 {
		return fmt.Errorf("database port is required")
	}
	if config.Username == "" {
		return fmt.Errorf("database username is required")
	}
	if config.Database == "" {
		return fmt.Errorf("database name is required")
	}
	if config.Driver == "" {
		return fmt.Errorf("database driver is required")
	}
	if config.MigrationPath != "" {
		if _, err := os.Stat(config.MigrationPath); os.IsNotExist(err) {
			return fmt.Errorf("migration path does not exist: %s", config.MigrationPath)
		}
	}
	return nil
}

func createDbConnection(config *config.DbConfig, logger *zerolog.Logger) (*sqlx.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.Username, config.Password, config.Database, config.Sslmode,
	)

	logger.Debug().
		Str("driver", config.Driver).
		Str("sslmode", config.Sslmode).
		Msg("Creating database connection")

	var db *sqlx.DB
	var err error

	for attempt := 1; attempt <= defaultRetryAttempts; attempt++ {
		logger.Debug().
			Int("attempt", attempt).
			Int("max_attempts", defaultRetryAttempts).
			Msg("Attempting to connect to database")

		db, err = sqlx.Connect(config.Driver, connStr)
		if err == nil {
			if err = db.Ping(); err == nil {
				logger.Info().
					Int("attempt", attempt).
					Msg("Database connection established successfully")

				return db, nil
			}
			db.Close()
		}

		logger.Warn().
			Err(err).
			Int("attempt", attempt).
			Msg("Database connection attempt failed")

		if attempt < defaultRetryAttempts {
			delay := defaultRetryDelay * time.Duration(attempt)

			logger.Warn().
				Dur("delay", delay).
				Msg("Retrying database connection")

			time.Sleep(delay)
		}
	}

	return nil, fmt.Errorf("failed to connect after %d attempts: %w", defaultRetryAttempts, err)
}

func (d *database) verifyHealth() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHealthCheckTimeout)
	defer cancel()

	if err := d.db.PingContext(ctx); err != nil {
		d.logger.Error().Err(err).Msg("Database ping failed")
		return fmt.Errorf("database ping failed: %w", err)
	}

	var result int
	if err := d.db.GetContext(ctx, &result, "SELECT 1"); err != nil {
		d.logger.Error().Err(err).Msg("Database query test failed")
		return fmt.Errorf("database query test failed: %w", err)
	}

	if d.config.MigrationPath != "" {
		var exists bool
		query := `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'schema_migrations')`
		if err := d.db.GetContext(ctx, &exists, query); err != nil {
			d.logger.Error().Err(err).Msg("Migration table check failed")
			return fmt.Errorf("migration table check failed: %w", err)
		}

		d.logger.Debug().
			Bool("migration_table_exists", exists).
			Msg("Migration table check completed")
	}

	return nil
}

func (d *database) runMigrations(ctx context.Context) error {
	if d.config.MigrationPath == "" {
		d.logger.Warn().Msg("No migration path configured, skipping migrations")
		return nil
	}

	d.logger.Debug().
		Str("migration_path", d.config.MigrationPath).
		Msg("Starting database migrations")

	if err := d.validateMigrationFiles(); err != nil {
		d.logger.Error().Err(err).Msg("Migration validation failed")
		return fmt.Errorf("migration validation failed: %w", err)
	}

	// Separate connection for migrations
	migrationDB, err := d.createMigrationConnection()
	if err != nil {
		d.logger.Error().Err(err).Msg("Failed to create migration connection")
		return fmt.Errorf("failed to create migration connection: %w", err)
	}
	defer migrationDB.Close()

	m, err := d.createMigrateInstance(migrationDB)
	if err != nil {
		d.logger.Error().Err(err).Msg("Failed to create migrate instance")
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer m.Close()

	if err := d.migrateWithLock(ctx, m, migrationDB); err != nil {
		d.logger.Error().Err(err).Msg("Migration execution failed")
		return fmt.Errorf("migration execution failed: %w", err)
	}

	d.logger.Debug().Msg("Migration process completed successfully")
	return nil
}

func (d *database) validateMigrationFiles() error {
	files, err := filepath.Glob(filepath.Join(d.config.MigrationPath, "*.sql"))
	if err != nil {
		return fmt.Errorf("failed to list migration files: %w", err)
	}

	if len(files) == 0 {
		d.logger.Warn().
			Str("migration_path", d.config.MigrationPath).
			Msg("No migration files found")
		return nil
	}

	d.logger.Debug().
		Int("file_count", len(files)).
		Str("migration_path", d.config.MigrationPath).
		Msg("Found migration files")

	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			d.logger.Error().
				Err(err).
				Str("file", file).
				Msg("Migration file not accessible")
			return fmt.Errorf("migration file not accessible: %s: %w", file, err)
		}
	}

	return nil
}

func (d *database) createMigrationConnection() (*sqlx.DB, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.config.Host, d.config.Port, d.config.Username, d.config.Password, d.config.Database, d.config.Sslmode,
	)

	db, err := sqlx.Connect(d.config.Driver, connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration connection: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration connection ping failed: %w", err)
	}

	return db, nil
}

func (d *database) createMigrateInstance(db *sqlx.DB) (*migrate.Migrate, error) {
	driver, err := postgres.WithInstance(db.DB, &postgres.Config{
		MigrationsTable: "schema_migrations",
		DatabaseName:    d.config.Database,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	absPath, err := filepath.Abs(d.config.MigrationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute migration path: %w", err)
	}

	sourceURL := fmt.Sprintf("file://%s", absPath)
	m, err := migrate.NewWithDatabaseInstance(sourceURL, "postgres", driver)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}

	return m, nil
}

func (d *database) migrateWithLock(ctx context.Context, m *migrate.Migrate, migrationDB *sqlx.DB) error {
	d.logger.Debug().Int64("lock_id", migrationLockID).Msg("Attempting to acquire advisory lock")

	acquired, err := d.acquireAdvisoryLock(ctx, migrationDB)
	if err != nil {
		d.logger.Error().Err(err).Msg("Failed to acquire advisory lock")
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}

	if !acquired {
		d.logger.Warn().Msg("Another instance is running migrations, waiting for completion")
		return d.waitForMigrations(ctx)
	}

	d.logger.Debug().Msg("Acquired advisory lock, proceeding with migrations")

	// Ensure lock released
	defer func() {
		if err := d.releaseAdvisoryLock(migrationDB); err != nil {
			d.logger.Error().Err(err).Msg("Failed to release advisory lock")
		} else {
			d.logger.Debug().Msg("Advisory lock released")
		}
	}()

	if err := d.logCurrentVersion(m); err != nil {
		d.logger.Warn().Err(err).Msg("Failed to get current migration version")
	}

	if err := d.applyMigrations(m); err != nil {
		return err
	}

	if err := d.logNewVersion(m); err != nil {
		d.logger.Warn().Err(err).Msg("Failed to get new migration version")
	}

	return nil
}

func (d *database) acquireAdvisoryLock(ctx context.Context, db *sqlx.DB) (bool, error) {
	var acquired bool
	query := "SELECT pg_try_advisory_lock($1)"

	if err := db.GetContext(ctx, &acquired, query, migrationLockID); err != nil {
		return false, fmt.Errorf("failed to execute advisory lock query: %w", err)
	}

	return acquired, nil
}

func (d *database) releaseAdvisoryLock(db *sqlx.DB) error {
	query := "SELECT pg_advisory_unlock($1)"
	_, err := db.Exec(query, migrationLockID)
	return err
}

func (d *database) waitForMigrations(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			d.logger.Error().Err(ctx.Err()).Msg("Context cancelled while waiting for migrations")
			return ctx.Err()
		case <-timeout:
			d.logger.Error().Msg("Timeout waiting for migrations to complete")
			return fmt.Errorf("timeout waiting for migrations to complete")
		case <-ticker.C:
			// Check if still running by trying to get version
			_, dirty, err := d.GetMigrationVersion()
			if err != nil {
				d.logger.Debug().Err(err).Msg("Error checking migration status, continuing to wait")
				continue
			}

			if !dirty {
				d.logger.Info().Msg("Migrations completed by another instance")
				return nil
			}
			d.logger.Debug().Msg("Migrations still in progress by another instance")
		}
	}
}

func (d *database) applyMigrations(m *migrate.Migrate) error {
	err := m.Up()

	if err != nil && err != migrate.ErrNoChange {
		d.logger.Error().Err(err).Msg("Failed to apply migrations")
		return fmt.Errorf("failed to apply migrations: %w", err)
	}

	if err == migrate.ErrNoChange {
		d.logger.Info().Msg("Database is up to date - no new migrations to apply")
	} else {
		d.logger.Info().Msg("Migrations applied successfully")
	}

	return nil
}

func (d *database) logNewVersion(m *migrate.Migrate) error {
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return err
	}

	if err != migrate.ErrNilVersion {
		d.logger.Info().
			Uint("version", version).
			Bool("dirty", dirty).
			Msg("New migration version")
	}

	return nil
}

func (d *database) logCurrentVersion(m *migrate.Migrate) error {
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return err
	}

	if err == migrate.ErrNilVersion {
		d.logger.Info().Msg("No migrations have been applied yet")
	} else {
		d.logger.Info().
			Uint("version", version).
			Bool("dirty", dirty).
			Msg("Current migration version")
	}

	return nil
}

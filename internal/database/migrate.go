package database

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	// PG advisory lock key for migrations
	migrationLockKey       = 1234567890
	migrationLockTimeout   = 60 * time.Second
	migrationCheckInterval = 5 * time.Second
)

type MigrationStatus string

const (
	MigrationStatusRunning   MigrationStatus = "running"
	MigrationStatusCompleted MigrationStatus = "completed"
	MigrationStatusFailed    MigrationStatus = "failed"
)

type MigrationLock struct {
	ID          uuid.UUID       `db:"id"`
	Status      MigrationStatus `db:"status"`
	InstanceID  string          `db:"instance_id"`
	StartedAt   time.Time       `db:"started_at"`
	CompletedAt *time.Time      `db:"completed_at"`
	Error       *string         `db:"error"`
	Version     *uint           `db:"version"`
}

type DistributedMigrator struct {
	db           *DB
	migrate      *migrate.Migrate
	instanceID   string
	lockAcquired bool
}

func NewDistributedMigrator(db *DB, migrationsDir string) (*DistributedMigrator, error) {

	if err := createMigrationLockTable(db); err != nil {
		return nil, fmt.Errorf("failed to create migration lock table: %w", err)
	}

	driver, err := postgres.WithInstance(db.DB.DB, &postgres.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to create postgres driver: %w", err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsDir),
		"postgres",
		driver,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}

	instanceID := fmt.Sprintf("%s-%d", uuid.New().String()[:8], time.Now().Unix())

	return &DistributedMigrator{
		db:         db,
		migrate:    m,
		instanceID: instanceID,
	}, nil
}

func (dm *DistributedMigrator) Up() error {
	return dm.runWithLock(func() error {
		return dm.migrate.Up()
	})
}

func (dm *DistributedMigrator) Down() error {
	return dm.runWithLock(func() error {
		return dm.migrate.Down()
	})
}

func (dm *DistributedMigrator) Version() (uint, bool, error) {
	return dm.migrate.Version()
}

func (dm *DistributedMigrator) Close() error {
	if dm.lockAcquired {
		dm.releaseLock()
	}

	sourceErr, dbErr := dm.migrate.Close()
	if sourceErr != nil {
		return sourceErr
	}

	return dbErr
}

// Removes migration lock entries that are older than 24 hours
func (dm *DistributedMigrator) CleanupStaleMigrations() error {
	query := `
        DELETE FROM migration_locks 
        WHERE status IN ($1, $2) AND started_at < $3`

	cutoff := time.Now().UTC().Add(-24 * time.Hour)

	result, err := dm.db.Exec(query, MigrationStatusCompleted, MigrationStatusFailed, cutoff)
	if err != nil {
		return fmt.Errorf("failed to cleanup old migration locks: %w", err)
	}

	if rowsAffected, err := result.RowsAffected(); err == nil && rowsAffected > 0 {
		log.Info().Int64("cleaned_records", rowsAffected).Msg("Cleaned up old migration lock records")
	}

	return nil
}

// Forcefully releases migration locks that are past their timeout.
// Also releases PG advisory lock.
func (dm *DistributedMigrator) ForceReleaseStaleLocks() error {
	cutoff := time.Now().UTC().Add(-migrationLockTimeout)

	query := `
        UPDATE migration_locks 
        SET status = $1, error = $2, completed_at = $3
        WHERE status = $4 AND started_at < $5`

	errorMsg := "Migration lock forcefully released due to timeout"

	result, err := dm.db.Exec(query,
		MigrationStatusFailed,
		errorMsg,
		time.Now().UTC(),
		MigrationStatusRunning,
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("failed to force release stale locks: %w", err)
	}

	if rowsAffected, err := result.RowsAffected(); err == nil && rowsAffected > 0 {
		log.Warn().Int64("released_locks", rowsAffected).Msg("Forcefully released stale migration locks")

		// Also release PG advisory lock
		dm.db.Exec("SELECT pg_advisory_unlock($1)", migrationLockKey)
	}

	return nil
}

func (dm *DistributedMigrator) runWithLock(migrationFunc func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), migrationLockTimeout)
	defer cancel()

	lockAcquired, err := dm.tryAcquireLock(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire migration lock: %w", err)
	}

	if !lockAcquired {
		// Another instance is running migrations, wait for it to complete
		log.Info().Str("instance_id", dm.instanceID).Msg("Another instance is running migrations, waiting...")
		return dm.waitForMigrationCompletion(ctx)
	}

	// We have advisory lock, run migrations
	dm.lockAcquired = true
	defer dm.releaseLock()

	log.Info().Str("instance_id", dm.instanceID).Msg("Acquired migration lock, running migrations")

	lockID, err := dm.recordMigrationStart()
	if err != nil {
		return fmt.Errorf("failed to record migration start: %w", err)
	}

	migrationErr := migrationFunc()

	if err := dm.recordMigrationCompletion(lockID, migrationErr); err != nil {
		log.Error().Err(err).Msg("Failed to record migration completion")
	}

	if migrationErr == migrate.ErrNoChange {
		log.Info().Msg("No new migrations to apply")
		return nil
	}

	if migrationErr != nil {
		return fmt.Errorf("migration failed: %w", migrationErr)
	}

	version, dirty, err := dm.migrate.Version()
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get migration version after completion")
	} else {
		log.Info().Uint("version", version).Bool("dirty", dirty).Msg("Migrations completed successfully")
	}

	return nil
}

func (dm *DistributedMigrator) tryAcquireLock(ctx context.Context) (bool, error) {
	var acquired bool
	query := "SELECT pg_try_advisory_lock($1)"

	err := dm.db.QueryRowContext(ctx, query, migrationLockKey).Scan(&acquired)
	if err != nil {
		return false, err
	}

	return acquired, nil
}

func (dm *DistributedMigrator) releaseLock() {
	if !dm.lockAcquired {
		return
	}

	query := "SELECT pg_advisory_unlock($1)"
	var released bool

	err := dm.db.QueryRow(query, migrationLockKey).Scan(&released)
	if err != nil {
		log.Error().Err(err).Msg("Failed to release advisory lock")
		return
	}

	if !released {
		log.Warn().Msg("Advisory lock was not held when trying to release")
	} else {
		log.Debug().Msg("Released migration advisory lock")
	}

	dm.lockAcquired = false
}

func (dm *DistributedMigrator) recordMigrationStart() (uuid.UUID, error) {
	lockID := uuid.New()

	query := `
        INSERT INTO migration_locks (id, status, instance_id, started_at) 
        VALUES ($1, $2, $3, $4)`

	_, err := dm.db.Exec(query, lockID, MigrationStatusRunning, dm.instanceID, time.Now().UTC())
	if err != nil {
		return uuid.Nil, err
	}

	return lockID, nil
}

func (dm *DistributedMigrator) recordMigrationCompletion(lockID uuid.UUID, migrationErr error) error {
	status := MigrationStatusCompleted
	var errorStr *string
	var version *uint

	if migrationErr != nil && migrationErr != migrate.ErrNoChange {
		status = MigrationStatusFailed
		errMsg := migrationErr.Error()
		errorStr = &errMsg
	} else {
		if v, _, err := dm.migrate.Version(); err == nil {
			version = &v
		}
	}

	query := `
        UPDATE migration_locks 
        SET status = $2, completed_at = $3, error = $4, version = $5
        WHERE id = $1`

	_, err := dm.db.Exec(query, lockID, status, time.Now().UTC(), errorStr, version)
	return err
}

func (dm *DistributedMigrator) waitForMigrationCompletion(ctx context.Context) error {
	ticker := time.NewTicker(migrationCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for migration completion: %w", ctx.Err())

		case <-ticker.C:
			var count int
			query := "SELECT COUNT(*) FROM migration_locks WHERE status = $1 AND started_at > $2"
			cutoff := time.Now().UTC().Add(-migrationLockTimeout)

			err := dm.db.QueryRow(query, MigrationStatusRunning, cutoff).Scan(&count)
			if err != nil {
				log.Error().Err(err).Msg("Failed to check migration status")
				continue
			}

			if count == 0 {
				log.Info().Msg("Migration completed by another instance")
				return nil
			}

			var failedCount int
			query = "SELECT COUNT(*) FROM migration_locks WHERE status = $1 AND started_at > $2"
			err = dm.db.QueryRow(query, MigrationStatusFailed, cutoff).Scan(&failedCount)
			if err != nil {
				log.Error().Err(err).Msg("Failed to check for failed migrations")
				continue
			}

			if failedCount > 0 {
				return fmt.Errorf("migration failed on another instance")
			}

			log.Debug().Msg("Still waiting for migrations to complete...")
		}
	}
}

func createMigrationLockTable(db *DB) error {
	query := `
        CREATE TABLE IF NOT EXISTS migration_locks (
            id UUID PRIMARY KEY,
            status VARCHAR(20) NOT NULL,
            instance_id VARCHAR(100) NOT NULL,
            started_at TIMESTAMPTZ NOT NULL,
            completed_at TIMESTAMPTZ,
            error TEXT,
            version INTEGER,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create migration_locks table: %w", err)
	}

	indexQuery := "CREATE INDEX IF NOT EXISTS idx_migration_locks_status_started ON migration_locks(status, started_at)"
	_, err = db.Exec(indexQuery)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to create migration_locks index")
	}

	return nil
}

package database

import (
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/rs/zerolog/log"
)

type Migrator struct {
	migrate *migrate.Migrate
}

func NewMigrator(db *DB, migrationsDir string) (*Migrator, error) {
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

	return &Migrator{
		migrate: m,
	}, nil
}

func (m *Migrator) Up() error {
	log.Info().Msg("Running database migrations up")

	err := m.migrate.Up()
	if err == migrate.ErrNoChange {
		log.Info().Msg("No new migrations to apply")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to run migrations up: %w", err)
	}

	version, dirty, err := m.migrate.Version()
	if err != nil {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	log.Info().Uint("version", version).Bool("dirty", dirty).Msg("Migrations applied successfully")
	return nil
}

func (m *Migrator) Down() error {
	log.Info().Msg("Running database migrations down")

	err := m.migrate.Down()
	if err == migrate.ErrNoChange {
		log.Info().Msg("No migrations to rollback")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to run migrations down: %w", err)
	}

	log.Info().Msg("Migrations rolled back successfully")
	return nil
}

func (m *Migrator) Version() (uint, bool, error) {
	return m.migrate.Version()
}

func (m *Migrator) Close() error {
	sourceErr, dbErr := m.migrate.Close()
	if sourceErr != nil {
		return sourceErr
	}
	return dbErr
}

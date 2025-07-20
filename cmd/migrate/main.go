package main

import (
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/thegenem0/atlas/internal/config"
	"github.com/thegenem0/atlas/internal/database"
	"github.com/thegenem0/atlas/internal/logging"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: migrate [up|down|version|cleanup|force-unlock]")
		os.Exit(1)
	}

	command := os.Args[1]

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logging.Setup("info", true)

	db, err := database.New(&cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}
	defer db.Close()

	migrator, err := database.NewDistributedMigrator(db, "migrations")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create migrator")
	}
	defer migrator.Close()

	switch command {
	case "up":
		if err := migrator.Up(); err != nil {
			log.Fatal().Err(err).Msg("Failed to run migrations up")
		}
		log.Info().Msg("Migrations completed successfully")

	case "down":
		if err := migrator.Down(); err != nil {
			log.Fatal().Err(err).Msg("Failed to run migrations down")
		}
		log.Info().Msg("Migrations rolled back successfully")

	case "version":
		version, dirty, err := migrator.Version()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get migration version")
		}
		fmt.Printf("Current migration version: %d (dirty: %t)\n", version, dirty)

	case "create":
		if len(os.Args) < 3 {
			fmt.Println("Usage: migrate create <migration_name>")
			os.Exit(1)
		}
		migrationName := os.Args[2]
		if err := createMigration(migrationName); err != nil {
			log.Fatal().Err(err).Msg("Failed to create migration")
		}
		log.Info().Str("name", migrationName).Msg("Migration files created")

	case "cleanup":
		if err := migrator.CleanupStaleMigrations(); err != nil {
			log.Fatal().Err(err).Msg("Failed to cleanup stale migrations")
		}
		log.Info().Msg("Cleaned up stale migration locks")

	case "force-unlock":
		fmt.Print("This will forcefully release stale migration locks. Continue? (y/N): ")
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Aborted")
			return
		}

		if err := migrator.ForceReleaseStaleLocks(); err != nil {
			log.Fatal().Err(err).Msg("Failed to force unlock migrations")
		}
		log.Info().Msg("Forcefully released stale migration locks")

	default:
		fmt.Printf("Unknown command: %s\n", command)
		fmt.Println("Available commands: up, down, version, create")
		os.Exit(1)
	}
}

func createMigration(name string) error {
	timestamp := fmt.Sprintf("%06d", time.Now().UnixNano()/1000000)

	upFile := fmt.Sprintf("migrations/%s_%s.up.sql", timestamp, name)
	downFile := fmt.Sprintf("migrations/%s_%s.down.sql", timestamp, name)

	upContent := fmt.Sprintf("-- Migration: %s\n-- Created at: %s\n\n-- Add your up migration here\n", name, "now")
	if err := os.WriteFile(upFile, []byte(upContent), 0644); err != nil {
		return err
	}

	downContent := fmt.Sprintf("-- Migration: %s (rollback)\n-- Created at: %s\n\n-- Add your down migration here\n", name, "now")
	if err := os.WriteFile(downFile, []byte(downContent), 0644); err != nil {
		return err
	}

	fmt.Printf("Created migration files:\n  %s\n  %s\n", upFile, downFile)
	return nil
}

package config

type DbConfig struct {
	Driver        string
	Host          string
	Port          int
	Username      string
	Password      string
	Database      string
	Sslmode       string
	MigrationPath string
}

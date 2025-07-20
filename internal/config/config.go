package config

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server" validate:"required"`
	Database DatabaseConfig `mapstructure:"database" validate:"required"`
	Logging  LoggingConfig  `mapstructure:"logging" validate:"required"`
	Security SecurityConfig `mapstructure:"security" validate:"required"`
}

type ServerConfig struct {
	Host         string `mapstructure:"host" validate:"required"`
	Port         int    `mapstructure:"port" validate:"min=1,max=65535"`
	ReadTimeout  int    `mapstructure:"read_timeout" validate:"min=1"`
	WriteTimeout int    `mapstructure:"write_timeout" validate:"min=1"`
}

type DatabaseConfig struct {
	Host         string `mapstructure:"host" validate:"required"`
	Port         int    `mapstructure:"port" validate:"min=1,max=65535"`
	Name         string `mapstructure:"name" validate:"required"`
	User         string `mapstructure:"user" validate:"required"`
	Password     string `mapstructure:"password" validate:"required"`
	SSLMode      string `mapstructure:"ssl_mode" validate:"required"`
	MaxOpenConns int    `mapstructure:"max_open_conns" validate:"min=1"`
	MaxIdleConns int    `mapstructure:"max_idle_conns" validate:"min=1"`
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.Name, d.SSLMode)
}

type LoggingConfig struct {
	Level  string `mapstructure:"level" validate:"required,oneof=trace debug info warn error fatal panic"`
	Pretty bool   `mapstructure:"pretty"`
}

type SecurityConfig struct {
	JWTSecret  string `mapstructure:"jwt_secret" validate:"required,min=32"`
	BcryptCost int    `mapstructure:"bcrypt_cost" validate:"min=10,max=15"`
	TokenTTL   int    `mapstructure:"token_ttl" validate:"min=300"`    // 5 minutes minimum
	RefreshTTL int    `mapstructure:"refresh_ttl" validate:"min=3600"` // 1 hour minimum
}

func Load() (*Config, error) {
	viper.SetConfigName("atlas")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./configs")
	viper.AddConfigPath(".")

	viper.SetEnvPrefix("ATLAS")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	setDefauls()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		// Config not found, relying on defaults and env vars
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	validate := validator.New()
	if err := validate.Struct(&cfg); err != nil {
		return nil, fmt.Errorf("failed to validate config: %w", err)
	}

	return &cfg, nil
}

func setDefauls() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", 30)
	viper.SetDefault("server.write_timeout", 30)

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.name", "atlas_identity")
	viper.SetDefault("database.user", "atlas")
	viper.SetDefault("database.password", "atlas")
	viper.SetDefault("database.ssl_mode", "disable")
	viper.SetDefault("database.max_open_conns", 25)
	viper.SetDefault("database.max_idle_conns", 5)

	// Logging defaults
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.pretty", true)

	// Security defaults
	viper.SetDefault("security.jwt_secret", "your-super-secret-jwt-key-change-in-production-please")
	viper.SetDefault("security.bcrypt_cost", 12)
	viper.SetDefault("security.token_ttl", 900)     // 15 minutes
	viper.SetDefault("security.refresh_ttl", 86400) // 24 hours
}

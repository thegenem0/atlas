package config

import (
	"fmt"

	"github.com/spf13/viper"
)

const (
	ConfigFileName = "atlas"
)

type Config struct {
	Server ServerConfig
	Db     DbConfig
}

func LoadConfig() (*Config, error) {
	var config Config

	viper.SetConfigName(ConfigFileName)
	viper.AddConfigPath(".")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	err := viper.Unmarshal(&config)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal config: %w", err)
	}

	return &config, nil
}

package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func Setup(level string, pretty bool) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(logLevel)
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if pretty {
		log.Logger = log.Output(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: time.RFC3339,
		})
	}

	// Add caller information for debug level and below
	if logLevel <= zerolog.DebugLevel {
		log.Logger = log.Logger.With().Caller().Logger()
	}
}

func WithRequestID(requestID string) *zerolog.Logger {
	logger := log.With().Str("request_id", requestID).Logger()
	return &logger
}

func WithTenantID(tenantID string) *zerolog.Logger {
	logger := log.With().Str("tenant_id", tenantID).Logger()
	return &logger
}

func WithUserID(userID string) *zerolog.Logger {
	logger := log.With().Str("user_id", userID).Logger()
	return &logger
}

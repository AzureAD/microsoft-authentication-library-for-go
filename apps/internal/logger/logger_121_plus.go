//go:build go1.21

package logger

import (
	"context"
	"log/slog"
	"os"
)

// logger struct for Go 1.21+ with full `slog` logging support.
type logger struct {
	logging *slog.Logger
}

// New creates a new logger instance for Go 1.21+ with full `slog` logging support.
// A default logger instance is provided if the loggerInterface is nil or there is an issue with type assertion of the loggerInterface
func NewLogger(loggerInterface interface{}) LoggerInterface {
	if loggerInterface == nil {
		// Provide a default logger instance
		defaultLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		return &logger{logging: defaultLogger}
	}
	if slogLogger, ok := loggerInterface.(*slog.Logger); ok {
		return &logger{logging: slogLogger}
	}
	// Handle the case where the type assertion fails
	defaultLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	return &logger{logging: defaultLogger}
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *logger) Log(ctx context.Context, level Level, message string, fields ...any) {
	if a == nil || a.logging == nil {
		return
	}
	var slogLevel slog.Level
	switch level {
	case Info:
		slogLevel = slog.LevelInfo
	case Err:
		slogLevel = slog.LevelError
	case Warn:
		slogLevel = slog.LevelWarn
	case Debug:
		slogLevel = slog.LevelDebug
	default:
		slogLevel = slog.LevelInfo
	}

	// Log the entry with the message and fields
	a.logging.Log(
		ctx,
		slogLevel,
		message,
		fields...,
	)
}

// Field creates a slog field for any value
func Field(key string, value any) any {
	return slog.Any(key, value)
}

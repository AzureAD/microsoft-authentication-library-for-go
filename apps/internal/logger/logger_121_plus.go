//go:build go1.21

package logger

import (
	"context"
	"fmt"
	"log/slog"
)

// logger struct for Go 1.21+ with full `slog` logging support.
type logger struct {
	logging *slog.Logger
}

// New creates a new logger instance
func NewLogger(loggerInterface interface{}) (LoggerInterface, error) {
	if loggerInterface == nil {
		return &logger{logging: nil}, nil
	}

	if loggerInterface, ok := loggerInterface.(*slog.Logger); ok {
		return &logger{logging: loggerInterface}, nil
	}

	return nil, fmt.Errorf("invalid input for Go 1.21+; expected *slog.Logger")
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *logger) Log(level Level, message string, fields ...any) {
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
		context.Background(),
		slogLevel,
		message,
		fields...,
	)
}

// Field creates a slog field for any value
func Field(key string, value any) any {
	return slog.Any(key, value)
}

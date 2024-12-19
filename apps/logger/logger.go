package logger

import (
	"context"
	"fmt"
	"log/slog"
)

// CallbackFunc defines the signature for callback functions
// we can only have one string to support azure sdk
type CallbackFunc func(level, message string)

type Level string

const (
	Info  Level = "info"
	Err   Level = "error"
	Warn  Level = "warn"
	Debug Level = "debug"
)

// Logger struct for Go 1.21+ with full `slog` logging support.
type Logger struct {
	logging *slog.Logger
}

// New creates a new logger instance
func New(slogLogger *slog.Logger) (*Logger, error) {
	// Return a logger instance for Go 1.21+
	if slogLogger == nil {
		return nil, fmt.Errorf("invalid input for Go 1.21+; expected *slog.Logger")
	}

	return &Logger{logging: slogLogger}, nil
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *Logger) Log(level Level, message string, fields ...any) {
	if a.logging == nil {
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

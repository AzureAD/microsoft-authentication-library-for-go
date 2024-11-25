//go:build go1.21

package logger

import (
	"context"
	"fmt"
	"log/slog"
)

// Logger struct for Go 1.21+ with full `slog` logging support.
type Logger struct {
	logging     *slog.Logger
	logCallback CallbackFunc
}

func New121(input interface{}) (*Logger, error) {
	if logger, ok := input.(*slog.Logger); ok {
		return &Logger{logging: logger}, nil
	}
	return nil, fmt.Errorf("invalid input for Go 1.21+; expected *slog.Logger")
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *Logger) Log(level string, message string, fields ...any) {
	if a.logging == nil {
		return
	}
	var slogLevel slog.Level
	switch level {
	case "info":
		slogLevel = slog.LevelInfo
	case "error":
		slogLevel = slog.LevelError
	case "warn":
		slogLevel = slog.LevelWarn
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

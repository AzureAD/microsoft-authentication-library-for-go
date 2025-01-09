//go:build go1.21

package slog

import (
	"log/slog"
)

type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type Logger = slog.Logger

// New creates a new logger instance for Go 1.21+ with full `slog` logging support.
// If nil is provided a default logger instance is created.
func New(slogLogger *slog.Logger) *Logger {
	if slogLogger == nil {
		defaultLogger := slog.Default()
		return defaultLogger
	}
	return slogLogger
}

// Field creates a slog field for any value
func Field(key string, value any) any {
	return slog.Any(key, value)
}

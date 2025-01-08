//go:build go1.21

package logger

import (
	"context"
	"log/slog"
	"os"
)

type Level = slog.Level

const (
	Debug = slog.LevelDebug
	Info  = slog.LevelInfo
	Warn  = slog.LevelWarn
	Error = slog.LevelError
)

type Logger struct {
	*slog.Logger
}

// New creates a new logger instance for Go 1.21+ with full `slog` logging support.
// If nil is provided a default logger instance is created.
func New(slogLogger *slog.Logger) *Logger {
	if slogLogger == nil {
		defaultLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
		return &Logger{defaultLogger}
	}
	return &Logger{slogLogger}
}

// Field creates a slog field for any value
func Field(key string, value any) any {
	return slog.Any(key, value)
}

// Log logs a message with the given level and arguments
func (l *Logger) Log(ctx context.Context, level Level, msg string, args ...any) {
	if l != nil {
		l.Logger.Log(ctx, level, msg, args...)
	}
}

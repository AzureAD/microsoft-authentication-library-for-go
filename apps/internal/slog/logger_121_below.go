//go:build !go1.21

package slog

import "context"

type Level int

type Logger struct{}

const (
	Debug Level = iota
	Info
	Warn
	Error
)

// These are all noop functions for go < 1.21
func New(logger *Logger) *Logger {
	return &Logger{}
}

func Field(key string, value any) any {
	return nil
}

func (*Logger) Log(context.Context, Level, string, ...any) {}
	// No-op
}

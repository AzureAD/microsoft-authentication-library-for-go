//go:build !go1.21

package slog

import (
	"context"
)

type Level int

type Logger struct{}

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type NopHandler struct{}

// These are all noop functions for go < 1.21
func New(h any) *Logger {
	return &Logger{}
}

func Any(key string, value any) any {
	return nil
}

func String(key, value string) any {
	return nil
}

func (*Logger) Log(ctx context.Context, level Level, msg string, args ...any) {}

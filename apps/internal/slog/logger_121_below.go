// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !go1.21

package slog

import (
	"context"
)

type NopHandler struct{}
type Logger struct{}

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

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

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build go1.21

package slog

import (
	"context"
	"log/slog"
)

type Level = slog.Level

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type Handler = slog.Handler
type Logger = slog.Logger

func (*NopHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (*NopHandler) Handle(context.Context, slog.Record) error { return nil }
func (h *NopHandler) WithAttrs([]slog.Attr) slog.Handler      { return h }
func (h *NopHandler) WithGroup(string) slog.Handler           { return h }

// New creates a new logger instance for Go 1.21+ with full `slog` logging support.
func New(h Handler) *Logger {
	return slog.New(h)
}

// Any creates a slog field for any value
func Any(key string, value any) any {
	return slog.Any(key, value)
}

// String creates a slog field for a string value
func String(key, value string) slog.Attr {
	return slog.String(key, value)
}

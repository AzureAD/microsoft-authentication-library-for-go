//go:build !go1.21

package logger

import "context"

type Level int

type Logger struct{}

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (*Logger) Log(context.Context, Level, string, ...any) {}

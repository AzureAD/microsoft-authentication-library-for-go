//go:build go1.18 && !go1.21

package logger

import "context"

type logger struct{}

func NewLogger(loggerInterface interface{}) LoggerInterface {
	return &logger{}
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *logger) Log(ctx context.Context, level Level, message string, fields ...any) {
	return
}

// Field creates a slog field for any value
func Field(key string, value any) any {
	return ""
}

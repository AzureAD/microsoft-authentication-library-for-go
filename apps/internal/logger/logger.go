package logger

import "context"

type Level string

const (
	Info  Level = "info"
	Err   Level = "error"
	Warn  Level = "warn"
	Debug Level = "debug"
)

// LoggerInterface defines the methods that a logger should implement
type LoggerInterface interface {
	Log(ctx context.Context, level Level, message string, fields ...any)
}

func New(loggerInterface interface{}) (LoggerInterface, error) {
	return NewLogger(loggerInterface)
}

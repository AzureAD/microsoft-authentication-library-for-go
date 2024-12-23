//go:build go1.18 && !go1.21

package logger

type logger struct{}

func NewLogger(loggerInterface interface{}) (LoggerInterface, error) {
	return &logger{}, nil
}

// Log method for Go 1.21+ with full support for structured logging and multiple log levels.
func (a *logger) Log(level Level, message string, fields ...any) {
	return
}

// Field creates a slog field for any value
func Field(key string, value any) any {
	return ""
}

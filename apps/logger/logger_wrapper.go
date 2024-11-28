package logger

import (
	"fmt"
	"runtime"
)

// CallbackFunc defines the signature for callback functions
// we can only have one string to support azure sdk
type CallbackFunc func(level, message string)

type Level string

const (
	Info  Level = "info"
	Err   Level = "err"
	Warn  Level = "warn"
	Debug Level = "debug"
)

// New created a new logger instance, determining the Go version and choosing the appropriate logging method.
func New(input interface{}) (*Logger, error) {
	if isGo121OrLater() {
		return New121(input)
	}

	if callback, ok := input.(func(level, message string)); ok {
		return &Logger{logCallback: callback}, nil
	}
	return nil, fmt.Errorf("invalid input for Go <=1.20; expected CallbackFunc")
}

// isGo121OrLater checks if the Go version is 1.21 or later.
func isGo121OrLater() bool {
	return runtime.Version() >= "go1.21"
}

//go:build go1.18 && !go1.20

package logger

import "fmt"

// Logger struct for Go versions <= 1.20.
type Logger struct {
	logCallback CallbackFunc
}

// Log method for Go <= 1.20, calls the callback function with log data.
func (a *Logger) Log(level string, message string, fields ...any) {
	// We don't use fields in this version
	if a.LogCallback != nil {
		a.logCallback(level, message)
	} else {
		fmt.Println("No callback function provided")
	}
}

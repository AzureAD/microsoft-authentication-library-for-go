package logger

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestLogger_Log_ConsoleOutput(t *testing.T) {
	// Capture the console output
	var buf bytes.Buffer
	handlerOptions := &slog.HandlerOptions{
		Level: slog.LevelDebug, // Set the log level to Debug to capture all log levels
	}
	slogLogger := slog.New(slog.NewTextHandler(&buf, handlerOptions))

	// Create a new logger instance
	logInstance, err := New(slogLogger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Log messages
	logInstance.Log(Info, "This is a info message via slog.", slog.String("username", "john_doe"), slog.Int("age", 30))
	logInstance.Log(Err, "This is a error message via slog.", slog.String("module", "user-service"), slog.Int("retry", 3))
	logInstance.Log(Warn, "This is a warn message via slog.", slog.Int("free_space_mb", 100))
	logInstance.Log(Debug, "This is a debug message via slog.", slog.String("module", "main"))

	// Check the output
	output := buf.String()
	expectedMessages := []string{
		"This is a info message via slog.",
		"This is a error message via slog.",
		"This is a warn message via slog.",
		"This is a debug message via slog.",
	}

	for _, msg := range expectedMessages {
		if !bytes.Contains([]byte(output), []byte(msg)) {
			t.Errorf("expected log message %q not found in output", msg)
		}
	}
}

// This test is to emulate what happens if the user has a go version < 1.21
// In this case, they will not have access to slog and will need to pass nil to the New function
func TestLogger_New_NilLogger(t *testing.T) {
	// Attempt to create a new logger instance with nil slog.Logger
	logInstance, err := New(nil)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if logInstance != nil {
		t.Fatalf("expected nil logInstance, got %v", logInstance)
	}
}
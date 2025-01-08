//go:build go1.21

package logger

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
)

func TestLogger_Log_ConsoleOutput(t *testing.T) {
	// Capture the console output
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug, // Set the log level to Debug to capture all log levels
	})

	// Create a new logger instance
	slogLogger := slog.New(handler)
	loggerInstance := New(slogLogger)

	// Log messages
	loggerInstance.Log(context.Background(), slog.LevelInfo, "This is an info message via slog.", slog.Any("username", "john_doe"), slog.Int("age", 30))
	loggerInstance.Log(context.Background(), slog.LevelError, "This is an error message via slog.", slog.String("module", "user-service"), slog.Int("retry", 3))
	loggerInstance.Log(context.Background(), slog.LevelWarn, "This is a warn message via slog.", slog.Int("free_space_mb", 100))
	loggerInstance.Log(context.Background(), slog.LevelDebug, "This is a debug message via slog.", slog.String("module", "main"))

	// Check the output
	output := buf.String()
	expectedMessages := []string{
		"This is an info message via slog.",
		"This is an error message via slog.",
		"This is a warn message via slog.",
		"This is a debug message via slog.",
	}

	for _, msg := range expectedMessages {
		if !bytes.Contains([]byte(output), []byte(msg)) {
			t.Errorf("expected log message %q not found in output", msg)
		}
	}
}

func TestNewLogger_NilLoggerInterface(t *testing.T) {
	// Test case where slogLogger is nil
	logInstance := New(nil)
	if logInstance == nil {
		t.Fatalf("expected non-nil logInstance, got nil")
	}
}

func TestNewLogger_ValidSlogLogger(t *testing.T) {
	// Test case where slogLogger is a valid *slog.Logger
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	slogLogger := slog.New(handler)
	logInstance := New(slogLogger)
	if logInstance == nil {
		t.Fatalf("expected non-nil logInstance, got nil")
	}
}

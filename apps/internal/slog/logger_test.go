//go:build go1.21

package slog

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
	expectedMessages := []struct {
		msg      string
		contains []string
	}{
		{"This is an info message via slog.", []string{`"username":"john_doe"`, `"age":30}`}},
		{"This is an error message via slog.", []string{`"module":"user-service"`, `"retry":3}`}},
		{"This is a warn message via slog.", []string{`"free_space_mb":100}`}},
		{"This is a debug message via slog.", []string{`"module":"main"`}},
	}

	for _, expected := range expectedMessages {
		if !bytes.Contains([]byte(output), []byte(expected.msg)) {
			t.Errorf("expected log message %q not found in output", expected.msg)
		}
		for _, attr := range expected.contains {
			if !bytes.Contains([]byte(output), []byte(attr)) {
				t.Errorf("expected attribute %q not found in output for message %q", attr, expected.msg)
			}
		}
	}
}

func TestNewLogger_NilLogger_Returns_Default(t *testing.T) {
	testLogger := slog.New(slog.Default().Handler())
	slog.SetDefault(testLogger)

	logInstance := New(nil)
	if logInstance == nil {
		t.Fatalf("expected non-nil logInstance, got nil")
	}

	if logInstance != testLogger {
		t.Fatalf("expected logInstance to be the default logger, got different logger")
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

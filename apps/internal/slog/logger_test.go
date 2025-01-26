// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

	// Create a new JSON handler
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug, // Set the log level to Debug to capture all log levels
	})

	// Create a new logger instance with the handler
	loggerInstance := New(handler)

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

func TestNewLogger_ValidSlogHandler(t *testing.T) {
	// Test case where handler is a valid slog.Handler
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logInstance := New(handler)
	if logInstance == nil {
		t.Fatalf("expected non-nil logInstance, got nil")
	}
}

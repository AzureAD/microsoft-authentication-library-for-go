package main

import (
	"context"
	"log/slog"
	"os"
)

func main() {
	// Test for Go 1.21+
	handlerOptions := &slog.HandlerOptions{}
	slogLogger := slog.New(slog.NewTextHandler(os.Stdout, handlerOptions))

	slogLogger.Log(context.Background(), slog.LevelInfo, "This is a info message via slog.", slog.String("username", "john_doe"), slog.Int("age", 30))
	slogLogger.Log(context.Background(), slog.LevelError, "This is a error message via slog.", slog.String("module", "user-service"), slog.Int("retry", 3))
	slogLogger.Log(context.Background(), slog.LevelWarn, "This is a warn message via slog.", slog.Int("free_space_mb", 100))
	slogLogger.Log(context.Background(), slog.LevelDebug, "This is a debug message via slog.", slog.String("module", "main"))
}

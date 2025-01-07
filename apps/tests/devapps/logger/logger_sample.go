package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/logger"
)

func main() {
	// Test for Go 1.21+
	handlerOptions := &slog.HandlerOptions{}
	slogLogger := slog.New(slog.NewTextHandler(os.Stdout, handlerOptions))
	logInstance := logger.New(slogLogger)

	logInstance.Log(context.Background(), logger.Info, "This is a info message via slog.", slog.String("username", "john_doe"), slog.Int("age", 30))
	logInstance.Log(context.Background(), logger.Err, "This is a error message via slog.", slog.String("module", "user-service"), slog.Int("retry", 3))
	logInstance.Log(context.Background(), logger.Warn, "This is a warn message via slog.", slog.Int("free_space_mb", 100))
	logInstance.Log(context.Background(), logger.Debug, "This is a debug message via slog.", slog.String("module", "main"))
}

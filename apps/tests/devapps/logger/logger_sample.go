package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/logger"
)

func main() {
	// Test for Go 1.21+
	handlerOptions := &slog.HandlerOptions{}
	slogLogger := slog.New(slog.NewTextHandler(os.Stdout, handlerOptions))
	logInstance, err := logger.New(slogLogger)
	if err != nil {
		fmt.Println("Error creating logger with slog:", err)
		return
	}

	logInstance.Log(logger.Info, "This is a info message via slog.", slog.String("username", "john_doe"), slog.Int("age", 30))
	logInstance.Log(logger.Err, "This is a error message via slog.", slog.String("module", "user-service"), slog.Int("retry", 3))
	logInstance.Log(logger.Warn, "This is a warn message via slog.", slog.Int("free_space_mb", 100))
	logInstance.Log(logger.Debug, "This is a debug message via slog.", slog.String("module", "main"))
}

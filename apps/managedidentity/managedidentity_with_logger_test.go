//go:build go1.21

package managedidentity

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// Custom log handler to capture log output
type BufferHandler struct {
	buf bytes.Buffer
}

// Custom log handler to capture log output and filter out info level logs
type FilteredBufferHandler struct {
	buf bytes.Buffer
}

func (h *BufferHandler) Enabled(ctx context.Context, level slog.Level) bool { return true }
func (h *BufferHandler) Handle(ctx context.Context, record slog.Record) error {
	h.buf.WriteString(record.Message + " ")
	record.Attrs(func(attr slog.Attr) bool {
		h.buf.WriteString(attr.Key + "=" + attr.Value.String() + " ")
		return true
	})
	return nil
}
func (h *BufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *BufferHandler) WithGroup(name string) slog.Handler       { return h }
func (h *FilteredBufferHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level == slog.LevelDebug
}
func (h *FilteredBufferHandler) Handle(ctx context.Context, record slog.Record) error {
	h.buf.WriteString(record.Message + " ")
	record.Attrs(func(attr slog.Attr) bool {
		h.buf.WriteString(attr.Key + "=" + attr.Value.String() + " ")
		return true
	})
	return nil
}
func (h *FilteredBufferHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *FilteredBufferHandler) WithGroup(name string) slog.Handler       { return h }

func TestClientLogging(t *testing.T) {
	// Set up mock client
	mockClient := mock.Client{}
	headers := http.Header{}
	headers.Set("www-authenticate", "Basic realm=/path/to/secret.key")
	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized), mock.WithHTTPHeader(headers))

	// Create a custom logger with BufferHandler
	bufferHandler := &BufferHandler{}
	customLogger := slog.New(bufferHandler)

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient), WithLogger(customLogger))
	if err != nil {
		t.Fatal(err)
	}

	// Call AcquireToken to trigger logging
	_, _ = client.AcquireToken(context.Background(), "https://resource")

	// Verify the log output
	logOutput := bufferHandler.buf.String()
	expectedLogMessage := "Managed Identity"
	if !strings.Contains(logOutput, expectedLogMessage) {
		t.Errorf("expected log message %q not found in output", expectedLogMessage)
	}
}

func TestClientLogging_NoLoggerProvided(t *testing.T) {
	// Set up mock client
	mockClient := mock.Client{}
	headers := http.Header{}
	headers.Set("www-authenticate", "Basic realm=/path/to/secret.key")
	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized), mock.WithHTTPHeader(headers))

	// Create a custom logger with BufferHandler to capture logs
	bufferHandler := &BufferHandler{}

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient))
	if err != nil {
		t.Fatal(err)
	}

	// Call AcquireToken to trigger logging
	_, _ = client.AcquireToken(context.Background(), "https://resource")

	// Verify that no logs are captured
	logOutput := bufferHandler.buf.String()
	if logOutput != "" {
		t.Errorf("expected no log output, but got: %q", logOutput)
	}
}

func TestClientLogging_CustomHandler(t *testing.T) {
	// Set up mock client
	mockClient := mock.Client{}
	headers := http.Header{}
	headers.Set("www-authenticate", "Basic realm=/path/to/secret.key")
	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized), mock.WithHTTPHeader(headers))

	// Create a custom logger with FilteredBufferHandler
	filteredBufferHandler := &FilteredBufferHandler{}
	customLogger := slog.New(filteredBufferHandler)

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient), WithLogger(customLogger))
	if err != nil {
		t.Fatal(err)
	}

	// Call AcquireToken to trigger logging
	_, _ = client.AcquireToken(context.Background(), "https://resource")

	// Verify the log output
	logOutput := filteredBufferHandler.buf.String()
	unexpectedLogMessage := "Managed Identity"
	if strings.Contains(logOutput, unexpectedLogMessage) {
		t.Errorf("unexpected log message %q found in output", unexpectedLogMessage)
	}
}

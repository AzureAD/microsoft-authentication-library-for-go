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

type BufferHandler struct {
	buf   bytes.Buffer
	level slog.Level
}

func (h *BufferHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return level <= h.level
}

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

func TestClientLogging(t *testing.T) {
	mockClient := mock.Client{}
	headers := http.Header{}
	headers.Set("www-authenticate", "Basic realm=/path/to/secret.key")
	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized), mock.WithHTTPHeader(headers))
	bufferHandler := &BufferHandler{}
	customLogger := slog.New(bufferHandler)

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient), WithLogger(customLogger, false))
	if err != nil {
		t.Fatal(err)
	}

	_, _ = client.AcquireToken(context.Background(), "https://resource")

	logOutput := bufferHandler.buf.String()
	expectedLogMessage := "Managed Identity"
	if !strings.Contains(logOutput, expectedLogMessage) {
		t.Errorf("expected log message %q not found in output", expectedLogMessage)
	}
}

func TestClientLogging_CustomHandler(t *testing.T) {
	mockClient := mock.Client{}
	headers := http.Header{}
	headers.Set("www-authenticate", "Basic realm=/path/to/secret.key")
	mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusUnauthorized), mock.WithHTTPHeader(headers))

	filteredBufferHandler := &BufferHandler{level: slog.LevelDebug}
	customLogger := slog.New(filteredBufferHandler)

	client, err := New(SystemAssigned(), WithHTTPClient(&mockClient), WithLogger(customLogger, false))
	if err != nil {
		t.Fatal(err)
	}

	_, _ = client.AcquireToken(context.Background(), "https://resource")

	logOutput := filteredBufferHandler.buf.String()
	unexpectedLogMessage := "Managed Identity"
	if strings.Contains(logOutput, unexpectedLogMessage) {
		t.Errorf("unexpected log message %q found in output", unexpectedLogMessage)
	}
}

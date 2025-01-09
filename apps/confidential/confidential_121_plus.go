//go:build go1.21

package confidential

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/slog"
)

// WithLogger allows for a custom slog logger to be set
// More information on slog here: https://pkg.go.dev/log/slog
// This can be used with confidential client when creating a New instance similar to this:
// customSlogLogger := slog.Default()
// confidentialClient, err := New(authority, clientID, cred, WithLogger(customSlogLogger))
func WithLogger(l slog.Logger) Option {
	return func(o *clientOptions) {
		o.logger = l
	}
}

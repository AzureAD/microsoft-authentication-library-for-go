//go:build go1.21

package confidential

import (
	"log/slog"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/logger"
)

// WithLogger allows for a custom logger to be set.
func WithLogger(l *slog.Logger) Option {
	return func(o *clientOptions) {
		o.logger = logger.New(l)
	}
}

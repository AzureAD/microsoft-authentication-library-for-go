//go:build go1.21

package managedidentity

import (
	"log/slog"
)

// WithLogger enables logging within the SDK
func WithLogger(l *slog.Logger) ClientOption {
	return func(o *ClientOptions) {
		o.logger = l
	}
}

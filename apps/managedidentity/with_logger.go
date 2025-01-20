//go:build go1.21

package managedidentity

import (
	"log/slog"
)

// WithLogger enables logging within the SDK
// When l is nil, client will use slog.Default()
// Panic will occur if slog.Default() returns nil
func WithLogger(l *slog.Logger) ClientOption {
	return func(o *ClientOptions) {
		o.logger = l
	}
}

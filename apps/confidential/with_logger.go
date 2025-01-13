//go:build go1.21

package confidential

import (
	"log/slog"
)

// WithLogger enables logging within the SDK
// When l is nil, client will use slog.Default()
// Panic will occur if slog.Default() returns nil
func WithLogger(l *slog.Logger) Option {
	return func(o *clientOptions) {
		o.logger = l
	}
}

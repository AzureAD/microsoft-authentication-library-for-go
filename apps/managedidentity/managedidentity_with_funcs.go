//go:build go1.21

package managedidentity

import (
	"log/slog"
)

// WithLogger enables logging within the SDK
// piiEnabled sets logging of Personally Identifiable Information (PII) within the SDK
func WithLogger(l *slog.Logger, piiEnabled bool) ClientOption {
	return func(o *ClientOptions) {
		o.logger = l
		o.piiLogging = piiEnabled
	}
}

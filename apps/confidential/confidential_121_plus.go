//go:build go1.21

package confidential

import (
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/logger"
)

//  WithLogger allows for a custom logger to be set.
func WithLogger(l interface{}) Option {
	return func(o *clientOptions) {
		logInstance, err := logger.New(l)
		if err != nil {
			fmt.Println("Error creating logger with slog:", err)
			return
		}
		o.logger = logInstance
	}
}

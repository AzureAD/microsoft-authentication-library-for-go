// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"net/http"
	"os"
	"strings"
)

func createServiceFabricAuthRequest(ctx context.Context, resource string, revokedToken string, cc []string) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Secret", os.Getenv(identityHeaderEnvVar))
	q := req.URL.Query()
	q.Set("api-version", serviceFabricAPIVersion)
	q.Set("resource", resource)
	if revokedToken != "" {
		q.Set("token_sha256_to_refresh", convertTokenToSHA256HashString(revokedToken))
	}

	if len(cc) > 0 {
		q.Set("xms_cc", strings.Join(cc, ","))
	}

	req.URL.RawQuery = q.Encode()
	return req, nil
}

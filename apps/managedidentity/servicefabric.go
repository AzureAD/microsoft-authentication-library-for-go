// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	clientCapabilitiesQueryParameter = "xms_cc"
	tokenSha256ToRefreshParameter    = "token_sha256_to_refresh"
)

func createServiceFabricAuthRequest(ctx context.Context, resource string, claims string, tokenSha256ToRefresh string, capabilities []string) (*http.Request, error) {
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

	// Add claims if provided
	if claims != "" {
		q.Set("claims", claims)
	}

	// Add token_sha256_to_refresh if provided
	if tokenSha256ToRefresh != "" {
		q.Set(tokenSha256ToRefreshParameter, tokenSha256ToRefresh)
	}

	// Add client capabilities if provided
	if len(capabilities) > 0 {
		q.Set(clientCapabilitiesQueryParameter, url.QueryEscape(strings.Join(capabilities, ",")))
	}

	req.URL.RawQuery = q.Encode()
	return req, nil
}

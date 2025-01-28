// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"fmt"
	"net/http"
	"os"
)

func createAzureMLAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	msiSecretEndpoint := os.Getenv(msiSecretEnvVar)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiSecretEndpoint, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("secret", os.Getenv(msiSecretEndpoint))
	q := req.URL.Query()
	q.Set("api-version", azureMLAPIVersion)
	q.Set("resource", resource)

	switch t := id.(type) {
	case UserAssignedClientID:
		q.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		return nil, fmt.Errorf("unsupported type %T", id)
	case UserAssignedObjectID:
		return nil, fmt.Errorf("unsupported type %T", id)
	case systemAssignedValue:
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}
	req.URL.RawQuery = q.Encode()
	return req, nil
}

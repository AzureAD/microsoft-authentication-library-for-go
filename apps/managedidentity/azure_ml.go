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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, os.Getenv(msiEndpointEnvVar), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("secret", os.Getenv(msiSecretEnvVar))
	q := req.URL.Query()
	q.Set(apiVersionQueryParameterName, azureMlApiVersion)
	q.Set(resourceQueryParameterName, resource)

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

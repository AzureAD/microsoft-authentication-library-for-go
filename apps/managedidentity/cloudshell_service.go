package managedidentity

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
)

func acquireTokenForCloudShell(ctx context.Context, client Client, resource string) (base.AuthResult, error) {
	req, err := createCloudShellAuthRequest(ctx, resource)
	if err != nil {
		return base.AuthResult{}, err
	}
	tokenResponse, err := client.getTokenForRequest(req)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(client.authParams, tokenResponse)
}

func createCloudShellAuthRequest(ctx context.Context, resource string) (*http.Request, error) {
	msiEndpoint := os.Getenv(msiEndpointEnvVar)
	msiEndpointParsed, err := url.Parse(msiEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", msiEndpoint, err)
	}

	msiParameters := msiEndpointParsed.Query()
	msiParameters.Set(resourceQueryParameterName, resource)
	msiDataEncoded := msiParameters.Encode()
	body := ioutil.NopCloser(strings.NewReader(msiDataEncoded))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, msiEndpointParsed.String(), body)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}

	req.Header.Set(metaHTTPHeaderName, "true")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

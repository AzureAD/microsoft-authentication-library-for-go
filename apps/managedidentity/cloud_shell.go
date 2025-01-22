// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func createCloudShellAuthRequest(ctx context.Context, resource string) (*http.Request, error) {
	msiEndpoint := os.Getenv(msiEndpointEnvVar)
	msiEndpointParsed, err := url.Parse(msiEndpoint)

	println("createCloudShellAuthRequest - msiEndpoint " + msiEndpoint)
	println("createCloudShellAuthRequest - msiEndpointParsed " + msiEndpoint)
	println("createCloudShellAuthRequest - resource " + resource)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", msiEndpoint, err)
	}

	data := url.Values{}
	data.Set(resourceQueryParameterName, resource)
	println("createCloudShellAuthRequest - dataGet " + data.Get(resourceQueryParameterName))
	msiDataEncoded := data.Encode()
	body := ioutil.NopCloser(strings.NewReader(msiDataEncoded))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, msiEndpointParsed.String(), body)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}

	req.Header.Set(metaHTTPHeaderName, "true")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

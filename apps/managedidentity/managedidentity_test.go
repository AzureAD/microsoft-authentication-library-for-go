// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

func fakeMIClient(mangedIdentityId ID, options ...ClientOption) (Client, error) {
	fakeClient, err := New(mangedIdentityId, options...)

	if err != nil {
		return Client{}, err
	}

	return fakeClient, nil
}

type errorClient struct{}

func (*errorClient) CloseIdleConnections() {}
func (*errorClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("expected no requests but received one for %s", req.URL.String())
}

type fakeClient struct{}

func (*fakeClient) CloseIdleConnections() {}
func (*fakeClient) Do(req *http.Request) (*http.Response, error) {
	w := http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(`{
      "access_token": "fakeToken",
      "refresh_token": "",
      "expires_in": "3599",
      "expires_on": "1506484173",
      "not_before": "1506480273",
      "token_type": "Bearer"
    }`)),
		Header: make(http.Header),
	}
	return &w, nil
}

func TestManagedIdentityIMDS_SAMISuccess(t *testing.T) {
	fakeHTTPClient := fakeClient{}

	client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

	if err != nil {
		t.Fatal(err)
	}

	result, err := client.AcquireToken(context.Background(), "fakeresource")

	if err != nil {
		t.Errorf("TestManagedIdentity: unexpected nil error from TestManagedIdentity")
	}

	expected := accesstokens.TokenResponse{
		AccessToken:  "fakeToken",
		ExpiresOn:    internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		ExtExpiresOn: internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		TokenType:    "Bearer",
	}
	if result.AccessToken != expected.AccessToken {
		t.Fatalf(`unexpected access token "%s"`, result.AccessToken)
	}

}
func TestManagedIdentityIMDS_SAMIError(t *testing.T) {
	fakeHTTPClient := errorClient{}

	client, err := fakeMIClient(SystemAssigned(), WithHTTPClient(&fakeHTTPClient))

	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.AcquireToken(context.Background(), "fakeresource"); err == nil {
		t.Errorf("TestManagedIdentity: Should have returned error for incorrect http request.")
	}

}
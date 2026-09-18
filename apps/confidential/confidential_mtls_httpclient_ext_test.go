// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential_test

import (
	"net/http"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// externalMtlsFactory is a genuine external implementation: this package can't import anything
// under apps/internal, so this compile-time assertion protects the public contract's usability.
type externalMtlsFactory struct {
	*http.Client
	calls int
}

func (f *externalMtlsFactory) NewMtlsClient(augment func(*http.Client) (*http.Client, error)) (confidential.HTTPClient, error) {
	f.calls++
	return augment(&http.Client{})
}

var _ confidential.MtlsHTTPClientFactory = (*externalMtlsFactory)(nil)

func TestMtlsHTTPClientFactoryIsImplementableExternally(t *testing.T) {
	factory := &externalMtlsFactory{Client: &http.Client{}}
	cred, err := confidential.NewCredFromSecret("secret")
	if err != nil {
		t.Fatalf("NewCredFromSecret() failed: %s", err)
	}
	if _, err := confidential.New(
		"https://login.microsoftonline.com/tenant",
		"client-id",
		cred,
		confidential.WithHTTPClient(factory),
	); err != nil {
		t.Fatalf("New() with an MtlsHTTPClientFactory failed: %s", err)
	}

	// Construction only detects the capability. The per-certificate cache invokes it lazily on the
	// first mutual-TLS token request.
	if factory.calls != 0 {
		t.Errorf("NewMtlsClient was called %d times during construction, want 0", factory.calls)
	}
}

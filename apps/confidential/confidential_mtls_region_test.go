// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// TestAcquireTokenByCredentialMtlsPoPAutoDetectedRegion is the end-to-end proof that a successfully
// auto-detected region reaches the mTLS token endpoint.
//
// WithAzureRegion(AutoDetectRegion()) stores a "TryAutoDetect" sentinel. Detection used to happen
// only inside instance discovery, which takes authority Info by value, so the resolved region was
// discarded when that function returned: the request kept the sentinel and fell back to the global
// mtlsauth.microsoft.com host, silently throwing away the region the caller asked for. MSAL .NET
// resolves the region during parameter initialization, before any host is built, so it never sees
// the sentinel.
func TestAcquireTokenByCredentialMtlsPoPAutoDetectedRegion(t *testing.T) {
	const region = "centralus"
	// detectRegion consults REGION_NAME before probing IMDS, which makes auto-detection deterministic
	// here without a network call.
	if err := os.Setenv("REGION_NAME", region); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("REGION_NAME")

	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"

	mockClient := mock.NewClient()
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
		WithAzureRegion(AutoDetectRegion()),
	)
	if err != nil {
		t.Fatal(err)
	}

	var gotURL *url.URL
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)),
		mock.WithCallback(func(r *http.Request) { gotURL = r.URL }),
	)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession()); err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	want := region + ".mtlsauth.microsoft.com"
	if gotURL.Host != want {
		t.Errorf("token endpoint host = %q, want %q (the auto-detected region was discarded)", gotURL.Host, want)
	}
	// Resolution happens on the per-request copy of AuthParams, so the client's own configuration
	// still reads back exactly what the caller set. Baking the detected region into the shared
	// client would make a one-off detection permanent for its whole lifetime.
	if got := client.base.AuthParams.AuthorityInfo.Region; got != AutoDetectRegion() {
		t.Errorf("client AuthorityInfo.Region = %q, want the caller's %q to be preserved", got, AutoDetectRegion())
	}
}

// TestAcquireTokenByCredentialMtlsPoPUndetectedRegion pins the documented fallback: when
// auto-detection yields nothing, the global mTLS endpoint is used. That is production-ready and is
// what MSAL .NET documents too ("mTLS Proof-of-Possession does not require a region"), so only a
// region that WAS detected must survive - an absent one must not become an error.
func TestAcquireTokenByCredentialMtlsPoPUndetectedRegion(t *testing.T) {
	if err := os.Setenv("REGION_NAME", ""); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("REGION_NAME")

	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"

	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetInstanceDiscoveryBody(lmo, tenant)))
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
	)
	if err != nil {
		t.Fatal(err)
	}

	var gotURL *url.URL
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)),
		mock.WithCallback(func(r *http.Request) { gotURL = r.URL }),
	)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession()); err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	if gotURL.Host != "mtlsauth.microsoft.com" {
		t.Errorf("token endpoint host = %q, want the global mtlsauth.microsoft.com", gotURL.Host)
	}
}

// TestAcquireTokenByCredentialMtlsPoPExplicitRegion covers the ordinary WithAzureRegion("centralus")
// case, which must be untouched by the auto-detection change: an explicitly configured region is
// never re-resolved or overwritten.
func TestAcquireTokenByCredentialMtlsPoPExplicitRegion(t *testing.T) {
	const region = "westus2"
	// A different value in the environment must not win over the explicit configuration.
	if err := os.Setenv("REGION_NAME", "centralus"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("REGION_NAME")

	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	tenant := "tenant"
	lmo := "login.microsoftonline.com"

	mockClient := mock.NewClient()
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		WithMtlsHTTPClient(mockMtlsFactory(mockClient)),
		WithAzureRegion(region),
	)
	if err != nil {
		t.Fatal(err)
	}

	var gotURL *url.URL
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)),
		mock.WithCallback(func(r *http.Request) { gotURL = r.URL }),
	)

	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession()); err != nil {
		t.Fatal(err)
	}
	if gotURL == nil {
		t.Fatal("token endpoint was never called")
	}
	want := region + ".mtlsauth.microsoft.com"
	if gotURL.Host != want {
		t.Errorf("token endpoint host = %q, want %q", gotURL.Host, want)
	}
}

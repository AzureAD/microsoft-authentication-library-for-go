// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
)

// blockingHTTPClient fails every request and counts the attempts, so a test can assert that a
// request was rejected before any network work happened rather than merely that it failed. It
// satisfies both the client interface WithHTTPClient takes and the http.RoundTripper an mTLS client
// needs, so one instance can watch both the ordinary and the mutual-TLS transport.
type blockingHTTPClient struct {
	mu    sync.Mutex
	calls int
}

func (c *blockingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return nil, c.record(req)
}

func (c *blockingHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, c.record(req)
}

func (c *blockingHTTPClient) CloseIdleConnections() {}

func (c *blockingHTTPClient) record(req *http.Request) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	return fmt.Errorf("unexpected request to %s", req.URL)
}

func (c *blockingHTTPClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// TestMtlsPoPInvalidForceRegionIsRejectedBeforeHTTP pins, on the mTLS PoP path, the property that
// upstream's regional authority hardening establishes for the bearer path: a region that is not a
// valid Azure region name never reaches a hostname.
//
// It matters here because MtlsTokenEndpoint interpolates the region straight into the token host
// ({region}.mtlsauth.microsoft.com), and because MSAL_FORCE_REGION is read from the process
// environment in New. The token endpoint is what receives the binding certificate, so the region
// must be checked before it is used to build that host.
//
// Two independent sites now reject it: AADInstanceDiscovery, reached from
// openIDConfigurationEndpoint's "the caller asked for a region" branch, and MtlsTokenEndpoint
// itself, which validates before concatenating (see TestMtlsTokenEndpointRejectsInvalidRegion). This
// test asserts the end-to-end property rather than either mechanism, so it keeps holding whichever
// one runs first.
//
// Instance discovery is disabled deliberately: that clears ValidateAuthority, which is the weakest
// configuration and the one where validation is most likely to be skipped.
func TestMtlsPoPInvalidForceRegionIsRejectedBeforeHTTP(t *testing.T) {
	if err := os.Setenv("MSAL_FORCE_REGION", "hostile.example/x"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv("MSAL_FORCE_REGION")

	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}

	blocked := &blockingHTTPClient{}
	client, err := New(fmt.Sprintf(authorityFmt, "login.microsoftonline.com", "tenant"), fakeClientID, cred,
		WithHTTPClient(blocked),
		WithInstanceDiscovery(false),
		WithMtlsHTTPClient(func(tls.Certificate) *http.Client {
			return &http.Client{Transport: blocked}
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	// Errorf rather than Fatalf so the "no request was made" half below is always evaluated too:
	// each half fails on its own, so neither can quietly stop pinning anything.
	if err == nil || !strings.Contains(err.Error(), "invalid region") {
		t.Errorf("AcquireTokenByCredential() error = %v, want an invalid region error", err)
	}
	if n := blocked.count(); n != 0 {
		t.Errorf("made %d network call(s) with an invalid region, want 0", n)
	}
}

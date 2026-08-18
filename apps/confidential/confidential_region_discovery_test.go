// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// routingHTTPClient answers by route instead of by queue position, so a test can observe how many
// requests a flow makes without the response order dictating the answer. Every request is recorded
// as "host/path" - the query string is dropped because only the host and route are under test.
type routingHTTPClient struct {
	mu        sync.Mutex
	requests  []string
	host      string
	tenant    string
	tokenBody []byte
}

func (c *routingHTTPClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.requests = append(c.requests, req.URL.Host+req.URL.Path)
	c.mu.Unlock()

	var body []byte
	switch {
	case strings.Contains(req.URL.Path, "/discovery/instance"):
		body = mock.GetInstanceDiscoveryBody(c.host, c.tenant)
	case strings.Contains(req.URL.Path, ".well-known/openid-configuration"):
		// Serve metadata for whichever host was actually asked, so the issuer matches the host the
		// resolver chose. That keeps this test measuring which host is contacted rather than
		// tripping issuer validation.
		body = mock.GetTenantDiscoveryBody(req.URL.Host, c.tenant)
	case strings.Contains(req.URL.Path, "/oauth2/v2.0/token"):
		body = c.tokenBody
	default:
		return nil, fmt.Errorf("unexpected request to %q", req.URL)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil
}

func (*routingHTTPClient) CloseIdleConnections() {}

type routingTransport struct{ client *routingHTTPClient }

func (t routingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.client.Do(req)
}

func (c *routingHTTPClient) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.requests))
	copy(out, c.requests)
	return out
}

// TestRegionAutoDetectFailureFollowsTheNoRegionPath pins a side effect of resolving the
// WithAzureRegion(AutoDetectRegion()) sentinel on the AuthParams instead of inside a by-value copy.
//
// Resolution now rewrites AuthorityInfo.Region for every flow, not just mTLS PoP, and
// openIDConfigurationEndpoint branches on that field: with a non-empty Region it asks instance
// discovery for the tenant discovery endpoint, otherwise it builds the canonical
// v2.0/.well-known/openid-configuration URI directly. Detection that finds nothing used to leave the
// literal "TryAutoDetect" sentinel in place, so the region branch was taken, instance discovery was
// called a second time, and its answer was thrown away by a dead write to a by-value parameter. Now
// the sentinel resolves to "" and the flow takes exactly the path it would have taken had the caller
// never asked for a region at all.
//
// That equivalence is the property worth pinning, and it is asserted directly: asking for a region
// and finding none must be indistinguishable from not asking. Bearer is covered alongside mTLS PoP
// because the branch is on the ordinary token path, not the mTLS one.
func TestRegionAutoDetectFailureFollowsTheNoRegionPath(t *testing.T) {
	const (
		host   = "login.microsoftonline.com"
		tenant = "tenant"
	)
	instanceDiscovery := host + "/common/discovery/instance"
	tenantDiscovery := host + "/" + tenant + "/v2.0/.well-known/openid-configuration"

	for _, test := range []struct {
		desc     string
		mtlsPoP  bool
		wantLast string
	}{
		{desc: "bearer", wantLast: host + "/" + tenant + "/oauth2/v2.0/token"},
		{desc: "mtls pop", mtlsPoP: true, wantLast: "mtlsauth.microsoft.com/" + tenant + "/oauth2/v2.0/token"},
	} {
		t.Run(test.desc, func(t *testing.T) {
			want := []string{instanceDiscovery, tenantDiscovery, test.wantLast}

			noRegion := acquireForRegionDiscovery(t, host, tenant, test.mtlsPoP, false)
			if !equalRequests(noRegion, want) {
				t.Fatalf("no region configured made requests\n\t%v\nwant\n\t%v", noRegion, want)
			}

			undetected := acquireForRegionDiscovery(t, host, tenant, test.mtlsPoP, true)
			if !equalRequests(undetected, want) {
				t.Fatalf("auto-detection finding nothing made requests\n\t%v\nwant\n\t%v", undetected, want)
			}

			// Stated as its own assertion because this is the invariant, not the literal list: a
			// region that was asked for but not found must behave like no region at all. Before
			// sentinel resolution moved onto AuthParams there was an extra instance discovery call
			// here whose result was discarded.
			if !equalRequests(noRegion, undetected) {
				t.Errorf("asking for a region and finding none diverged from not asking\n\tundetected: %v\n\tno region:  %v", undetected, noRegion)
			}
		})
	}
}

// acquireForRegionDiscovery runs one acquisition and returns the "host/path" of every request it
// made. When autoDetect is set the client asks for auto-detection and detection finds nothing.
func acquireForRegionDiscovery(t *testing.T, host, tenant string, mtlsPoP, autoDetect bool) []string {
	t.Helper()

	// REGION_NAME is consulted before IMDS and has its spaces stripped, so a blank-but-set value
	// makes detection resolve to nothing without a network probe - deterministic even on a machine
	// where IMDS would answer. It also sidesteps the detection memo entirely, since the environment
	// variable is deliberately never memoized, so nothing leaks into or out of this test.
	// TestDetectRegionBlankEnvironmentResolvesToNothing pins that seam.
	if err := os.Unsetenv("REGION_NAME"); err != nil {
		t.Fatal(err)
	}
	if autoDetect {
		if err := os.Setenv("REGION_NAME", "   "); err != nil {
			t.Fatal(err)
		}
		defer os.Unsetenv("REGION_NAME")
	}

	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}

	client := &routingHTTPClient{host: host, tenant: tenant}
	opts := []Option{WithHTTPClient(client)}
	var acquireOpts []AcquireByCredentialOption
	if mtlsPoP {
		client.tokenBody = mtlsPoPTokenBody("mtls-access-token", 3600)
		opts = append(opts, WithMtlsHTTPClient(func(tls.Certificate) *http.Client {
			return &http.Client{Transport: routingTransport{client: client}}
		}))
		acquireOpts = append(acquireOpts, WithMtlsProofOfPossession())
	} else {
		client.tokenBody = mock.GetAccessTokenBody("access-token", "", "", "", 3600, 0)
	}
	if autoDetect {
		opts = append(opts, WithAzureRegion(AutoDetectRegion()))
	}

	app, err := New(fmt.Sprintf(authorityFmt, host, tenant), fakeClientID, cred, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.AcquireTokenByCredential(context.Background(), tokenScope, acquireOpts...); err != nil {
		t.Fatal(err)
	}
	return client.recorded()
}

func equalRequests(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

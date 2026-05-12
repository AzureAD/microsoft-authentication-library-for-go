// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package oauth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// crossCloudDiscoveryBody returns a discovery doc whose issuer matches the
// authority host (so issuer validation passes) but whose token_endpoint and
// authorization_endpoint can be overridden to point anywhere (to simulate a
// tampered or hijacked discovery response).
func crossCloudDiscoveryBody(authorityHost, tenant, tokenEndpoint, authorizationEndpoint string) []byte {
	if tokenEndpoint == "" {
		tokenEndpoint = fmt.Sprintf("https://%s/%s/oauth2/v2.0/token", authorityHost, tenant)
	}
	if authorizationEndpoint == "" {
		authorizationEndpoint = fmt.Sprintf("https://%s/%s/oauth2/v2.0/authorize", authorityHost, tenant)
	}
	return []byte(fmt.Sprintf(
		`{"token_endpoint":%q,"authorization_endpoint":%q,"issuer":%q}`,
		tokenEndpoint,
		authorizationEndpoint,
		fmt.Sprintf("https://%s/%s/v2.0", authorityHost, tenant),
	))
}

func newAuthorityInfoForTest(t *testing.T, host, tenant string) authority.Info {
	t.Helper()
	authorityURI := fmt.Sprintf("https://%s/%s/", host, tenant)
	info, err := authority.NewInfoFromAuthorityURI(authorityURI, false /*validateAuthority*/, true /*disableInstanceDiscovery*/)
	if err != nil {
		t.Fatalf("NewInfoFromAuthorityURI: %v", err)
	}
	return info
}

// requestCountingClient wraps a mock client to record the number of POST
// requests issued. The cross-cloud check must trip BEFORE any credential POST
// to the spoofed endpoint.
type requestCountingClient struct {
	inner *mock.Client
	posts int32
}

func (c *requestCountingClient) Do(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		atomic.AddInt32(&c.posts, 1)
	}
	return c.inner.Do(req)
}
func (c *requestCountingClient) CloseIdleConnections() { c.inner.CloseIdleConnections() }

// TestResolveEndpoints_CrossCloudTokenEndpointRefused verifies that when the
// configured authority is a known Microsoft host, a discovery doc whose
// token_endpoint resolves to a different sovereign cloud is refused, and
// that NO credential POST was issued to the spoofed endpoint.
func TestResolveEndpoints_CrossCloudTokenEndpointRefused(t *testing.T) {
	host := "login.microsoftonline.com" // Public cloud authority
	tenant := "contoso"
	spoofedTokenEndpoint := "https://login.partner.microsoftonline.cn/contoso/oauth2/v2.0/token"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, spoofedTokenEndpoint, "")))
	counter := &requestCountingClient{inner: mc}

	client := New(counter)
	info := newAuthorityInfoForTest(t, host, tenant)
	_, err := client.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected cross-cloud rejection, got nil error")
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Errorf("error should mention token_endpoint; got: %v", err)
	}
	if !strings.Contains(err.Error(), spoofedTokenEndpoint) {
		t.Errorf("error should contain spoofed endpoint %q; got: %v", spoofedTokenEndpoint, err)
	}
	if got := atomic.LoadInt32(&counter.posts); got != 0 {
		t.Errorf("expected zero POSTs to the spoofed endpoint, got %d", got)
	}
}

// TestResolveEndpoints_CustomEndpointUnderKnownAuthorityRefused verifies that
// a discovery doc whose token_endpoint points at an attacker-controlled
// custom domain is refused when the configured authority is a known Microsoft
// host.
func TestResolveEndpoints_CustomEndpointUnderKnownAuthorityRefused(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "contoso"
	spoofedTokenEndpoint := "https://attacker.example.com/oauth2/v2.0/token"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, spoofedTokenEndpoint, "")))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)
	_, err := client.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected rejection for custom endpoint under known-MS authority, got nil")
	}
	if !strings.Contains(err.Error(), spoofedTokenEndpoint) {
		t.Errorf("error should contain spoofed endpoint %q; got: %v", spoofedTokenEndpoint, err)
	}
}

// TestResolveEndpoints_CrossCloudAuthorizationEndpointRefused verifies that
// the same-cloud check also fires on the authorization_endpoint, not just
// token_endpoint.
func TestResolveEndpoints_CrossCloudAuthorizationEndpointRefused(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "contoso"
	spoofedAuthEndpoint := "https://login.partner.microsoftonline.cn/contoso/oauth2/v2.0/authorize"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, "", spoofedAuthEndpoint)))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)
	_, err := client.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected rejection for cross-cloud authorization_endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "authorization_endpoint") {
		t.Errorf("error should mention authorization_endpoint; got: %v", err)
	}
	if !strings.Contains(err.Error(), spoofedAuthEndpoint) {
		t.Errorf("error should contain spoofed endpoint %q; got: %v", spoofedAuthEndpoint, err)
	}
}

// TestResolveEndpoints_CustomIdpEndpointAllowed verifies that custom-domain
// authorities (not in the known-host map) are NOT constrained by the
// same-cloud check. A custom OIDC IdP can publish its own endpoints freely.
func TestResolveEndpoints_CustomIdpEndpointAllowed(t *testing.T) {
	host := "idp.crosscloudtest-1.example.com"
	tenant := "tenant"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, "", "")))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)
	endpoints, err := client.ResolveEndpoints(context.Background(), info, "")
	if err != nil {
		t.Fatalf("expected success for custom OIDC authority, got %v", err)
	}
	if !strings.HasPrefix(endpoints.TokenEndpoint, "https://"+host) {
		t.Errorf("unexpected token endpoint %q for custom authority %q", endpoints.TokenEndpoint, host)
	}
}

// TestResolveEndpoints_TamperedDocNotCached verifies the ordering requirement:
// a tampered discovery doc must NOT poison the cache. After a cross-cloud
// rejection, a subsequent call with a clean doc for the same authority must
// re-issue discovery (and succeed).
func TestResolveEndpoints_TamperedDocNotCached(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "tampercheck-tenant"
	spoofed := "https://login.partner.microsoftonline.cn/" + tenant + "/oauth2/v2.0/token"

	mc := mock.NewClient()
	// First call: tampered.
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, spoofed, "")))
	// Second call: clean — should be re-fetched because the first call must
	// not have cached the tampered response.
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, "", "")))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)

	if _, err := client.ResolveEndpoints(context.Background(), info, ""); err == nil {
		t.Fatal("first call: expected cross-cloud rejection, got nil")
	}
	endpoints, err := client.ResolveEndpoints(context.Background(), info, "")
	if err != nil {
		t.Fatalf("second call (clean doc): expected success, got %v", err)
	}
	wantTokenPrefix := "https://" + host
	if !strings.HasPrefix(endpoints.TokenEndpoint, wantTokenPrefix) {
		t.Errorf("second call: unexpected token endpoint %q", endpoints.TokenEndpoint)
	}
}

// TestResolveEndpoints_MalformedTokenEndpointRefused verifies fail-closed
// behavior of the same-cloud check when the discovery doc returns a
// token_endpoint that is not a parseable absolute URL. For a known-MS
// authority, MSAL must refuse rather than silently fall through.
func TestResolveEndpoints_MalformedTokenEndpointRefused(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "malformed-tenant"
	malformed := "not-a-url"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, malformed, "")))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)
	_, err := client.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected rejection for malformed token_endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Errorf("error should mention token_endpoint; got: %v", err)
	}
	if !strings.Contains(err.Error(), malformed) {
		t.Errorf("error should contain malformed value %q; got: %v", malformed, err)
	}
}

// TestResolveEndpoints_MalformedAuthorizationEndpointRefused mirrors the
// token_endpoint case for the second endpoint covered by the same-cloud check.
func TestResolveEndpoints_MalformedAuthorizationEndpointRefused(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "malformed-authz-tenant"
	malformed := "not-a-url"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, "", malformed)))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)
	_, err := client.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected rejection for malformed authorization_endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "authorization_endpoint") {
		t.Errorf("error should mention authorization_endpoint; got: %v", err)
	}
	if !strings.Contains(err.Error(), malformed) {
		t.Errorf("error should contain malformed value %q; got: %v", malformed, err)
	}
}

// TestResolveEndpoints_HTTPSchemeEndpointRefused verifies that a discovery doc
// returning a same-cloud host but downgraded to plain http is refused. The
// same-cloud check must require https for known-MS authorities.
func TestResolveEndpoints_HTTPSchemeEndpointRefused(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "http-downgrade-tenant"
	downgraded := "http://login.windows.net/" + tenant + "/oauth2/v2.0/token"

	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(crossCloudDiscoveryBody(host, tenant, downgraded, "")))
	counter := &requestCountingClient{inner: mc}

	client := New(counter)
	info := newAuthorityInfoForTest(t, host, tenant)
	_, err := client.ResolveEndpoints(context.Background(), info, "")
	if err == nil {
		t.Fatal("expected rejection for http token_endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https; got: %v", err)
	}
	if got := atomic.LoadInt32(&counter.posts); got != 0 {
		t.Errorf("expected zero POSTs to downgraded endpoint, got %d", got)
	}
}

// TestResolveEndpoints_SameCloudAliasAllowed verifies that a discovery doc
// publishing a token_endpoint on a DIFFERENT host alias of the SAME sovereign
// cloud (e.g. login.windows.net for a login.microsoftonline.com authority) is
// accepted by the same-cloud check.
func TestResolveEndpoints_SameCloudAliasAllowed(t *testing.T) {
	host := "login.microsoftonline.com"
	tenant := "samecloudalias-tenant"
	// Different host but same Public cloud.
	aliasTokenEndpoint := "https://login.windows.net/" + tenant + "/oauth2/v2.0/token"

	// Issuer must still pass ValidateIssuerMatchesAuthority — login.windows.net
	// is a same-cloud alias and is accepted by Rule 2b.
	body := []byte(fmt.Sprintf(
		`{"token_endpoint":%q,"authorization_endpoint":%q,"issuer":%q}`,
		aliasTokenEndpoint,
		fmt.Sprintf("https://%s/%s/oauth2/v2.0/authorize", host, tenant),
		fmt.Sprintf("https://login.windows.net/%s/v2.0", tenant),
	))
	mc := mock.NewClient()
	mc.AppendResponse(mock.WithBody(body))

	client := New(mc)
	info := newAuthorityInfoForTest(t, host, tenant)
	endpoints, err := client.ResolveEndpoints(context.Background(), info, "")
	if err != nil {
		t.Fatalf("expected acceptance for same-cloud alias, got %v", err)
	}
	if endpoints.TokenEndpoint != aliasTokenEndpoint {
		t.Errorf("unexpected token endpoint %q", endpoints.TokenEndpoint)
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

// fakeClientInfo returns a base64url-encoded client_info JSON with the given uid and utid.
func fakeClientInfo(uid, utid string) string {
	raw := fmt.Sprintf(`{"uid":"%s","utid":"%s"}`, uid, utid)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// --- FMI Tests: Assertion Context ---

func TestFMIPath_AssertionCallbackReceivesFMIPath(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
	fmiPath := "agent-app-id-123"
	accessToken := "fmi-token"

	var receivedFMIPath string
	cred := NewCredFromAssertionCallback(func(ctx context.Context, opts AssertionRequestOptions) (string, error) {
		receivedFMIPath = opts.FMIPath
		return "fake-assertion", nil
	})

	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(tenant, authority), "", "", 3600, 0)))

	client, err := New(authority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope, WithFMIPath(fmiPath))
	if err != nil {
		t.Fatalf("AcquireTokenByCredential failed: %v", err)
	}

	if receivedFMIPath != fmiPath {
		t.Fatalf("assertion callback received FMIPath %q, want %q", receivedFMIPath, fmiPath)
	}
}

func TestFMIPath_AssertionCallbackReceivesEmptyFMIPathWhenNotSet(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
	accessToken := "regular-token"

	var receivedFMIPath string
	cred := NewCredFromAssertionCallback(func(ctx context.Context, opts AssertionRequestOptions) (string, error) {
		receivedFMIPath = opts.FMIPath
		return "fake-assertion", nil
	})

	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody(accessToken, mock.GetIDToken(tenant, authority), "", "", 3600, 0)))

	client, err := New(authority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
	if err != nil {
		t.Fatalf("AcquireTokenByCredential failed: %v", err)
	}

	if receivedFMIPath != "" {
		t.Fatalf("assertion callback received FMIPath %q without WithFMIPath, want empty", receivedFMIPath)
	}
}

// --- FMI Tests: Extended cache key ---

func TestFMIPath_DifferentFMIPathsProduceDifferentCacheEntries(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	client, err := New(authority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// First FMI path
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("token-agent-A", mock.GetIDToken(tenant, authority), "", "", 3600, 0)))
	ar1, err := client.AcquireTokenByCredential(ctx, tokenScope, WithFMIPath("agentA"))
	if err != nil {
		t.Fatal(err)
	}

	// Second FMI path — should NOT be served from cache
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("token-agent-B", mock.GetIDToken(tenant, authority), "", "", 3600, 0)))
	ar2, err := client.AcquireTokenByCredential(ctx, tokenScope, WithFMIPath("agentB"))
	if err != nil {
		t.Fatal(err)
	}

	if ar1.AccessToken == ar2.AccessToken {
		t.Fatal("different fmi_path values should produce different cache entries")
	}

	// Same FMI path again — should be served from cache
	ar3, err := client.AcquireTokenByCredential(ctx, tokenScope, WithFMIPath("agentA"))
	if err != nil {
		t.Fatal(err)
	}
	if ar3.AccessToken != "token-agent-A" {
		t.Fatalf("expected cached token for agentA, got %q", ar3.AccessToken)
	}
	if ar3.Metadata.TokenSource != TokenSourceCache {
		t.Fatal("expected token from cache on repeated fmi_path request")
	}
}

func TestFMIPath_FMITokenDoesNotCollideWithRegularToken(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	authority := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	client, err := New(authority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// Regular token (no FMI)
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("regular-token", mock.GetIDToken(tenant, authority), "", "", 3600, 0)))
	ar1, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}

	// FMI token (same scopes, same client) — must NOT collide with regular
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("fmi-token", mock.GetIDToken(tenant, authority), "", "", 3600, 0)))
	ar2, err := client.AcquireTokenByCredential(ctx, tokenScope, WithFMIPath("someAgent"))
	if err != nil {
		t.Fatal(err)
	}

	if ar1.AccessToken == ar2.AccessToken {
		t.Fatal("FMI token should not collide with regular token at same scope")
	}

	// Regular should still be from cache
	ar3, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if ar3.AccessToken != "regular-token" {
		t.Fatal("regular token was overwritten by FMI token")
	}
}

// --- FIC Tests: Protocol Correctness ---

func TestUserFIC_SendsCorrectGrantType(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	var requestBody string
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("user-token", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("user-oid", tenant), 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			body, _ := readAndRestoreBody(r)
			requestBody = string(body)
		}),
	)

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(),
		[]string{"https://graph.microsoft.com/.default"},
		"federated-credential-t2",
		WithUserObjectID("user-oid-value"),
	)
	if err != nil {
		t.Fatalf("AcquireTokenByUserFederatedIdentityCredential failed: %v", err)
	}

	assertBodyContains(t, requestBody, "grant_type", "user_fic")
	assertBodyContains(t, requestBody, "user_federated_identity_credential", "federated-credential-t2")
	assertBodyContains(t, requestBody, "user_id", "user-oid-value")
	assertBodyContains(t, requestBody, "client_info", "1")
}

func TestUserFIC_ScopeIncludesOidcScopes(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	var requestBody string
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("user-token", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("uid1", tenant), 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			body, _ := readAndRestoreBody(r)
			requestBody = string(body)
		}),
	)

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(),
		[]string{"https://graph.microsoft.com/.default"},
		"t2-assertion",
		WithUserFICUsername("user@contoso.com"),
	)
	if err != nil {
		t.Fatalf("AcquireTokenByUserFederatedIdentityCredential failed: %v", err)
	}

	// Scope should include openid, offline_access, profile
	assertBodyContains(t, requestBody, "scope", "openid")
	assertBodyContains(t, requestBody, "scope", "offline_access")
	assertBodyContains(t, requestBody, "scope", "profile")
	assertBodyContains(t, requestBody, "scope", "https://graph.microsoft.com/.default")
}

// --- FIC Tests: User Identification ---

func TestUserFIC_WithUsername_SendsUsernameNotUserID(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	var requestBody string
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("user-token", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("uid1", tenant), 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			body, _ := readAndRestoreBody(r)
			requestBody = string(body)
		}),
	)

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(),
		tokenScope,
		"assertion-value",
		WithUserFICUsername("user@contoso.com"),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertBodyContains(t, requestBody, "username", "user@contoso.com")
	assertBodyNotContains(t, requestBody, "user_id")
}

func TestUserFIC_WithObjectID_SendsUserIDNotUsername(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	var requestBody string
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("user-token", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("uid1", tenant), 3600, 0)),
		mock.WithCallback(func(r *http.Request) {
			body, _ := readAndRestoreBody(r)
			requestBody = string(body)
		}),
	)

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(),
		tokenScope,
		"assertion-value",
		WithUserObjectID("00000000-0000-0000-0000-000000000001"),
	)
	if err != nil {
		t.Fatal(err)
	}

	assertBodyContains(t, requestBody, "user_id", "00000000-0000-0000-0000-000000000001")
	assertBodyNotContains(t, requestBody, "username")
}

// --- FIC Tests: Cache Behavior ---

func TestUserFIC_TokenStoredInUserCache(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("user-token-1", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("user-oid-1", tenant), 3600, 0)))

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	ar, err := client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(),
		tokenScope,
		"assertion-t2",
		WithUserObjectID("user-oid-1"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if ar.AccessToken != "user-token-1" {
		t.Fatalf("expected user-token-1, got %q", ar.AccessToken)
	}
	// Account should be populated (user cache)
	if ar.Account.HomeAccountID == "" {
		t.Fatal("expected account to be populated (user cache storage)")
	}
}

func TestUserFIC_CacheHit_UseAcquireTokenSilentForCaching(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("user-token", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("user-oid", tenant), 3600, 0)))

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// First call — hits the network, stores in user cache
	ar1, err := client.AcquireTokenByUserFederatedIdentityCredential(ctx, tokenScope, "t2", WithUserObjectID("user-oid"))
	if err != nil {
		t.Fatal(err)
	}
	if ar1.Account.HomeAccountID == "" {
		t.Fatal("expected account with HomeAccountID after first call")
	}

	// Developer uses AcquireTokenSilent for subsequent calls
	ar2, err := client.AcquireTokenSilent(ctx, tokenScope, WithSilentAccount(ar1.Account))
	if err != nil {
		t.Fatal(err)
	}
	if ar2.AccessToken != ar1.AccessToken {
		t.Fatalf("expected cached token %q, got %q", ar1.AccessToken, ar2.AccessToken)
	}
}

func TestUserFIC_MultipleCallsHitNetwork(t *testing.T) {
	lmo := "login.microsoftonline.com"
	tenant := "test-tenant"
	auth := fmt.Sprintf(authorityFmt, lmo, tenant)
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	httpCalls := 0
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("user-token-1", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("uid", tenant), 3600, 0)),
		mock.WithCallback(func(r *http.Request) { httpCalls++ }),
	)

	client, err := New(auth, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// First call
	_, err = client.AcquireTokenByUserFederatedIdentityCredential(ctx, tokenScope, "t2", WithUserObjectID("uid"))
	if err != nil {
		t.Fatal(err)
	}
	if httpCalls != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", httpCalls)
	}

	// Second call — always hits network (developer should use AcquireTokenSilent for caching)
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("user-token-2", mock.GetIDToken(tenant, auth), "rt", fakeClientInfo("uid", tenant), 3600, 0)),
		mock.WithCallback(func(r *http.Request) { httpCalls++ }),
	)

	ar2, err := client.AcquireTokenByUserFederatedIdentityCredential(ctx, tokenScope, "t2", WithUserObjectID("uid"))
	if err != nil {
		t.Fatal(err)
	}
	if httpCalls != 2 {
		t.Fatalf("expected 2 HTTP calls total, got %d", httpCalls)
	}
	if ar2.AccessToken != "user-token-2" {
		t.Fatalf("expected new token from second call, got %q", ar2.AccessToken)
	}
}

// --- FIC Tests: Input Validation ---

func TestUserFIC_EmptyAssertion_ReturnsError(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(), tokenScope, "", WithUserObjectID("oid"),
	)
	if err == nil {
		t.Fatal("expected error for empty assertion")
	}
}

func TestUserFIC_NoUserIdentifier_ReturnsError(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(), tokenScope, "assertion",
	)
	if err == nil {
		t.Fatal("expected error when neither WithUserObjectID nor WithUserFICUsername is specified")
	}
}

func TestUserFIC_BothUserIdentifiers_ReturnsError(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}

	mockClient := mock.NewClient()
	client, err := New(fakeAuthority, fakeClientID, cred, WithHTTPClient(mockClient), WithInstanceDiscovery(false))
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireTokenByUserFederatedIdentityCredential(
		context.Background(), tokenScope, "assertion",
		WithUserObjectID("oid"), WithUserFICUsername("user@contoso.com"),
	)
	if err == nil {
		t.Fatal("expected error when both WithUserObjectID and WithUserFICUsername are specified")
	}
}

// --- Helper functions ---

func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func assertBodyContains(t *testing.T, body, key, expectedValue string) {
	t.Helper()
	parsed, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}
	values := parsed[key]
	if len(values) == 0 {
		t.Fatalf("expected %q in request body, but not found. Body: %s", key, body)
	}
	// For scope (space-delimited multi-value), check membership; for all others, check exact match
	if key == "scope" {
		for _, v := range values {
			if strings.Contains(v, expectedValue) {
				return
			}
		}
		t.Fatalf("expected scope to contain %q, got %v", expectedValue, values)
	} else {
		if values[0] != expectedValue {
			t.Fatalf("expected %q = %q, got %q", key, expectedValue, values[0])
		}
	}
}

func assertBodyNotContains(t *testing.T, body, key string) {
	t.Helper()
	parsed, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("failed to parse request body: %v", err)
	}
	if _, present := parsed[key]; present {
		t.Fatalf("expected %q NOT to be in request body, but found value %q", key, parsed.Get(key))
	}
}

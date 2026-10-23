// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

func TestSignedAssertionImplicitMtlsAcrossSupportedGrants(t *testing.T) {
	for _, test := range []struct {
		name    string
		acquire func(Client) (AuthResult, error)
	}{
		{
			name: "client credential",
			acquire: func(client Client) (AuthResult, error) {
				return client.AcquireTokenByCredential(context.Background(), tokenScope)
			},
		},
		{
			name: "authorization code",
			acquire: func(client Client) (AuthResult, error) {
				return client.AcquireTokenByAuthCode(context.Background(), "code", "https://localhost", tokenScope)
			},
		},
		{
			name: "on behalf of",
			acquire: func(client Client) (AuthResult, error) {
				return client.AcquireTokenOnBehalfOf(context.Background(), "user-assertion", tokenScope)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf, key := newSelfSignedCert(t, test.name)
			var calls int32
			var callbackOptions AssertionRequestOptions
			cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
				atomic.AddInt32(&calls, 1)
				callbackOptions = opts
				return SignedAssertion{
					Assertion:          "bound-assertion",
					BindingCertificate: tlsCertFor(leaf, key),
				}, nil
			})

			u, err := url.Parse(bearerMtlsControlAuthority)
			if err != nil {
				t.Fatal(err)
			}
			router := &bearerMtlsRouter{host: u.Host, tenant: strings.Trim(u.Path, "/")}
			var factoryCert tls.Certificate
			client, err := New(bearerMtlsControlAuthority, fakeClientID, cred,
				WithHTTPClient(router),
				withTestMtlsClient(func(cert tls.Certificate) *http.Client {
					factoryCert = cert
					return &http.Client{Transport: bearerMtlsRoundTripper{router: router}}
				}),
			)
			if err != nil {
				t.Fatal(err)
			}

			result, err := test.acquire(client)
			if err != nil {
				t.Fatal(err)
			}
			if got := atomic.LoadInt32(&calls); got != 1 {
				t.Fatalf("callback invoked %d times, want exactly 1", got)
			}
			if factoryCert.Leaf == nil || !factoryCert.Leaf.Equal(leaf) {
				t.Error("mTLS client factory didn't receive the callback's binding certificate")
			}
			request := router.tokenRequest()
			if request == nil {
				t.Fatal("no token request was recorded")
			}
			if !strings.HasPrefix(request.Host, "mtlsauth.") {
				t.Errorf("token request host = %q, want mtlsauth.*", request.Host)
			}
			if requestID := router.tokenRequestHeader().Get("client-request-id"); requestID != callbackOptions.CorrelationID {
				t.Errorf("request client-request-id = %q, callback CorrelationID = %q", requestID, callbackOptions.CorrelationID)
			}
			form := router.tokenRequestBody()
			if got := form.Get("client_assertion"); got != "bound-assertion" {
				t.Errorf("client_assertion = %q, want bound-assertion", got)
			}
			if got := form.Get("client_assertion_type"); !strings.HasSuffix(got, "jwt-pop") {
				t.Errorf("client_assertion_type = %q, want jwt-pop", got)
			}
			if _, ok := form["token_type"]; ok {
				t.Error("implicit mTLS must keep the final token Bearer")
			}
			if _, ok := form["req_cnf"]; ok {
				t.Error("mTLS binds through the handshake and must not send req_cnf")
			}
			if result.Metadata.TokenType != "Bearer" {
				t.Errorf("Metadata.TokenType = %q, want Bearer", result.Metadata.TokenType)
			}
			if result.BindingCertificate != nil {
				t.Error("a final Bearer token must not expose a binding certificate")
			}
		})
	}
}

func TestSignedAssertionImplicitMtlsSilentRefresh(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "silent-refresh")
	var calls int32
	var callbackOptions []AssertionRequestOptions
	cred := NewCredFromSignedAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		callbackOptions = append(callbackOptions, opts)
		return SignedAssertion{
			Assertion:          "bound-assertion",
			BindingCertificate: tlsCertFor(leaf, key),
		}, nil
	})

	const (
		tenant = "tenant"
		lmo    = "login.microsoftonline.com"
	)
	clientInfo := base64.RawStdEncoding.EncodeToString([]byte(`{"uid":"uid","utid":"utid"}`))
	idToken := mock.GetIDToken(tenant, fmt.Sprintf(authorityFmt, lmo, tenant))
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))

	var forms []url.Values
	record := func(r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		forms = append(forms, form)
	}
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("seed", idToken, "refresh-token", clientInfo, 1, 0)),
		mock.WithCallback(record),
	)

	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		withTestMtlsClient(mockMtlsFactory(mockClient)),
		WithInstanceDiscovery(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := client.AcquireTokenByAuthCode(context.Background(), "code", "https://localhost", tokenScope)
	if err != nil {
		t.Fatal(err)
	}

	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("refreshed", idToken, "refresh-token", clientInfo, 3600, 0)),
		mock.WithCallback(record),
	)
	refreshed, err := client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(seed.Account))
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "refreshed" {
		t.Errorf("AccessToken = %q, want refreshed", refreshed.AccessToken)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("callback invoked %d times, want one snapshot for auth code and one for silent refresh", got)
	}
	if len(callbackOptions) != 2 || callbackOptions[0].CorrelationID == "" || callbackOptions[1].CorrelationID == "" {
		t.Fatalf("callback options = %+v, want two populated acquisition snapshots", callbackOptions)
	}
	if len(forms) != 2 {
		t.Fatalf("recorded %d token requests, want 2", len(forms))
	}
	for i, form := range forms {
		if got := form.Get("client_assertion_type"); !strings.HasSuffix(got, "jwt-pop") {
			t.Errorf("request %d client_assertion_type = %q, want jwt-pop", i, got)
		}
		if _, ok := form["token_type"]; ok {
			t.Errorf("request %d unexpectedly sent token_type", i)
		}
		if _, ok := form["req_cnf"]; ok {
			t.Errorf("request %d unexpectedly sent req_cnf", i)
		}
	}
	if got := forms[1].Get("grant_type"); got != "refresh_token" {
		t.Errorf("silent request grant_type = %q, want refresh_token", got)
	}
}

func TestSignedAssertionBearerAndMtlsPoPCacheIsolation(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "cache-isolation")
	var calls int32
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		return SignedAssertion{
			Assertion:          "bound-assertion",
			BindingCertificate: tlsCertFor(leaf, key),
		}, nil
	})

	const (
		tenant = "tenant"
		lmo    = "login.microsoftonline.com"
	)
	mockClient := mock.NewClient()
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	var forms []url.Values
	record := func(r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		forms = append(forms, form)
	}
	mockClient.AppendResponse(
		mock.WithBody(mock.GetAccessTokenBody("bearer-token", "", "", "", 3600, 0)),
		mock.WithCallback(record),
	)
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(mockClient),
		withTestMtlsClient(mockMtlsFactory(mockClient)),
		WithInstanceDiscovery(false),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	bearer, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-pop-token", 3600)),
		mock.WithCallback(record),
	)
	pop, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	bearerAgain, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	popAgain, err := client.AcquireTokenByCredential(ctx, tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}

	if bearer.Metadata.TokenSource != TokenSourceIdentityProvider || pop.Metadata.TokenSource != TokenSourceIdentityProvider {
		t.Error("the first acquisition of each token type must reach the identity provider")
	}
	if bearerAgain.Metadata.TokenSource != TokenSourceCache || popAgain.Metadata.TokenSource != TokenSourceCache {
		t.Error("the second acquisition of each token type must use its own cache entry")
	}
	if bearer.AccessToken != "bearer-token" || bearerAgain.AccessToken != bearer.AccessToken {
		t.Errorf("Bearer tokens = %q/%q, want bearer-token from identity provider then cache", bearer.AccessToken, bearerAgain.AccessToken)
	}
	if pop.AccessToken != "mtls-pop-token" || popAgain.AccessToken != pop.AccessToken {
		t.Errorf("mtls_pop tokens = %q/%q, want mtls-pop-token from identity provider then cache", pop.AccessToken, popAgain.AccessToken)
	}
	if bearer.BindingCertificate != nil || bearerAgain.BindingCertificate != nil {
		t.Error("Bearer results must not expose a binding certificate")
	}
	if pop.BindingCertificate == nil || popAgain.BindingCertificate == nil {
		t.Error("mtls_pop results must expose their binding certificate")
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Errorf("callback invoked %d times, want one snapshot per acquisition", got)
	}
	if len(forms) != 2 {
		t.Fatalf("recorded %d token requests, want exactly 2", len(forms))
	}
	if _, ok := forms[0]["token_type"]; ok {
		t.Error("the final Bearer request unexpectedly sent token_type")
	}
	if got := forms[1].Get("token_type"); got != "mtls_pop" {
		t.Errorf("PoP request token_type = %q, want mtls_pop", got)
	}
}

func TestSignedAssertionImplicitBearerRejectsMtlsPoPBeforeCache(t *testing.T) {
	leaf, key := newSelfSignedCert(t, "unexpected-token-type")
	var calls int32
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		atomic.AddInt32(&calls, 1)
		return SignedAssertion{
			Assertion:          "bound-assertion",
			BindingCertificate: tlsCertFor(leaf, key),
		}, nil
	})
	srv := newMtlsHandshakeServer(t, mtlsPoPTokenBody("wrong-token-type", 3600))
	client := handshakeTestClient(t, cred, srv)

	for i := 0; i < 2; i++ {
		_, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
		if err == nil {
			t.Fatal("a final Bearer acquisition accepted an mtls_pop response")
		}
		if !strings.Contains(err.Error(), "Bearer") || !strings.Contains(err.Error(), "mtls_pop") {
			t.Errorf("error %q doesn't identify the expected and actual token types", err)
		}
	}
	if got := srv.tokenCalls(); got != 2 {
		t.Errorf("token endpoint called %d times, want 2: the rejected response must not be cached", got)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Errorf("callback invoked %d times, want one snapshot per acquisition", got)
	}
}

func TestSignedAssertionImplicitBearerRotationKeepsSnapshotPaired(t *testing.T) {
	first, firstKey := newSelfSignedCert(t, "snapshot-a")
	second, secondKey := newSelfSignedCert(t, "snapshot-b")
	var calls int32
	cred := NewCredFromSignedAssertionCallback(func(context.Context, AssertionRequestOptions) (SignedAssertion, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			return SignedAssertion{
				Assertion:          "assertion-a",
				BindingCertificate: tlsCertFor(first, firstKey),
			}, nil
		}
		return SignedAssertion{
			Assertion:          "assertion-b",
			BindingCertificate: tlsCertFor(second, secondKey),
		}, nil
	})

	srvA := newMtlsHandshakeServer(t, mock.GetAccessTokenBody("token-a", "", "", "", 3600, 0))
	srvB := newMtlsHandshakeServer(t, mock.GetAccessTokenBody("token-b", "", "", "", 3600, 0))
	factoryA, factoryB := srvA.clientFactory(), srvB.clientFactory()
	const (
		tenant = "tenant"
		lmo    = "login.microsoftonline.com"
	)
	client, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(discoveryClient{host: lmo, tenant: tenant}),
		withTestMtlsClient(func(cert tls.Certificate) *http.Client {
			if cert.Leaf != nil && cert.Leaf.Equal(second) {
				return factoryB(cert)
			}
			return factoryA(cert)
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	resultA, err := client.AcquireTokenByCredential(context.Background(), []string{"scope-a"})
	if err != nil {
		t.Fatal(err)
	}
	resultB, err := client.AcquireTokenByCredential(context.Background(), []string{"scope-b"})
	if err != nil {
		t.Fatal(err)
	}
	if resultA.AccessToken != "token-a" || resultB.AccessToken != "token-b" {
		t.Errorf("AccessTokens = %q/%q, want token-a/token-b", resultA.AccessToken, resultB.AccessToken)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("callback invoked %d times, want exactly once per acquisition", got)
	}
	if got := srvA.presented(t); !got.Equal(first) {
		t.Error("first acquisition didn't present certificate A")
	}
	if got := srvB.presented(t); !got.Equal(second) {
		t.Error("second acquisition didn't present certificate B")
	}
	if got := srvA.form(t).Get("client_assertion"); got != "assertion-a" {
		t.Errorf("first request client_assertion = %q, want assertion-a paired with certificate A", got)
	}
	if got := srvB.form(t).Get("client_assertion"); got != "assertion-b" {
		t.Errorf("second request client_assertion = %q, want assertion-b paired with certificate B", got)
	}
}

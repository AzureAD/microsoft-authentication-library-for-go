// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

// TestMtlsPoPRejectsAuthenticationScheme pins the deliberate divergence from MSAL .NET recorded on
// WithMtlsProofOfPossession: combining the two options is an error rather than mTLS PoP silently
// replacing the caller's scheme. The rejection must happen before anything is sent, so a caller
// never gets a token issued under a scheme they didn't ask for.
func TestMtlsPoPRejectsAuthenticationScheme(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	counter := &countingClient{}
	client, err := New(fmt.Sprintf(authorityFmt, "login.microsoftonline.com", "tenant"), fakeClientID, cred,
		WithHTTPClient(counter),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Both orderings, because option application order must not decide which one wins.
	for _, test := range []struct {
		desc string
		opts []AcquireByCredentialOption
	}{
		{
			desc: "scheme first",
			opts: []AcquireByCredentialOption{
				WithAuthenticationScheme(mock.NewTestAuthnScheme()),
				WithMtlsProofOfPossession(),
			},
		},
		{
			desc: "mTLS PoP first",
			opts: []AcquireByCredentialOption{
				WithMtlsProofOfPossession(),
				WithAuthenticationScheme(mock.NewTestAuthnScheme()),
			},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			_, err := client.AcquireTokenByCredential(context.Background(), tokenScope, test.opts...)
			if err == nil {
				t.Fatal("AcquireTokenByCredential = nil error, want the option combination to be rejected")
			}
			// The message has to name both options, because that's the only way a caller can tell
			// which of their calls to change.
			for _, want := range []string{"WithAuthenticationScheme", "WithMtlsProofOfPossession", "cannot be combined"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
			if n := counter.count(); n != 0 {
				t.Errorf("the combination was rejected only after %d network call(s); it must be rejected up front", n)
			}
		})
	}
}

// TestAuthenticationSchemeAloneStillWorks is the control for the rejection above: without
// WithMtlsProofOfPossession, a caller-supplied scheme is still honored and still formats the access
// token.
func TestAuthenticationSchemeAloneStillWorks(t *testing.T) {
	cred, err := NewCredFromSecret(fakeSecret)
	if err != nil {
		t.Fatal(err)
	}
	client, err := fakeClient(accesstokens.TokenResponse{
		AccessToken:   token,
		ExpiresOn:     time.Now().Add(time.Hour),
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		TokenType:     "TokenType",
	}, cred, fakeAuthority)
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithAuthenticationScheme(mock.NewTestAuthnScheme()))
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf(mock.Authnschemeformat, token); res.AccessToken != want {
		t.Fatalf("AccessToken = %q, want %q", res.AccessToken, want)
	}
}

// TestMtlsPoPAloneStillWorks is the other control: without WithAuthenticationScheme, mTLS PoP still
// installs its own scheme and issues an mtls_pop token.
func TestMtlsPoPAloneStillWorks(t *testing.T) {
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

	var gotBody url.Values
	mockClient.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	mockClient.AppendResponse(
		mock.WithBody(mtlsPoPTokenBody("mtls-access-token", 3600)),
		mock.WithCallback(func(r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody, _ = url.ParseQuery(string(b))
		}),
	)

	res, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithMtlsProofOfPossession())
	if err != nil {
		t.Fatal(err)
	}
	if got := gotBody.Get("token_type"); got != "mtls_pop" {
		t.Errorf("token_type = %q, want mtls_pop", got)
	}
	if res.Metadata.TokenType != "mtls_pop" {
		t.Errorf("result token type = %q, want mtls_pop", res.Metadata.TokenType)
	}
}

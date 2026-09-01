// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package base

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// mtlsPoPParams builds the AuthParams of an mTLS proof-of-possession request carrying the given
// binding certificate.
func mtlsPoPParams(cert *tls.Certificate) authority.AuthParams {
	return authority.AuthParams{
		AuthorityInfo:   authority.Info{Host: fakeAuthority},
		ClientID:        fakeClientID,
		HomeAccountID:   "uid.utid",
		Scopes:          testScopes,
		AuthnScheme:     &authority.BearerAuthenticationScheme{},
		IsMtlsPoP:       true,
		MtlsBindingCert: cert,
	}
}

func mtlsPoPToken() accesstokens.TokenResponse {
	return accesstokens.TokenResponse{
		AccessToken:   "at",
		ClientInfo:    accesstokens.ClientInfo{UID: "uid", UTID: "utid"},
		GrantedScopes: accesstokens.Scopes{Slice: testScopes},
		IDToken:       fakeIDToken,
		RefreshToken:  "rt",
	}
}

// TestAuthResultFromTokenRequiresBindingCertificate proves an mTLS PoP acquisition that cannot
// resolve a usable binding certificate fails, and fails before anything is written to the cache.
//
// AuthResult.BindingCertificate is documented as the certificate the caller must present to the
// resource. A result with a nil one is a certificate-bound token the caller has no way to use, which
// surfaces later as an opaque TLS failure or 401 rather than at the point the problem occurred.
//
// The ordering is the substantive half. Resolving the certificate after the write would leave the
// unusable token in the cache, and every later acquisition would be served from there without ever
// re-running this path -- so a single transient failure would poison the cache for the token's whole
// lifetime.
func TestAuthResultFromTokenRequiresBindingCertificate(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		name string
		cert *tls.Certificate
	}{
		{"nil certificate", nil},
		{"no DER chain", &tls.Certificate{}},
		{"empty leaf", &tls.Certificate{Certificate: [][]byte{{}}}},
		{"unparsable leaf", &tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := fakeClient(t)

			_, err := client.AuthResultFromToken(ctx, mtlsPoPParams(test.cert), mtlsPoPToken())
			if err == nil {
				t.Fatal("expected an error: the caller would otherwise receive a certificate-bound token with no certificate to present")
			}
			if !strings.Contains(err.Error(), "binding certificate") {
				t.Errorf("error should name the problem, got: %v", err)
			}

			// Nothing may have been cached. If it was, the unusable token is served from the cache
			// from now on and this code path never runs again.
			accounts, err := client.AllAccounts(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(accounts) != 0 {
				t.Errorf("an unusable mTLS PoP token was written to the cache: %d account(s) present", len(accounts))
			}
		})
	}
}

// TestAuthResultFromTokenBindingCertificateSuccess guards the guard: a well-formed binding
// certificate must still produce a result, be cached, and carry the certificate through.
func TestAuthResultFromTokenBindingCertificateSuccess(t *testing.T) {
	ctx := context.Background()
	leaf, key := selfSignedCert(t)
	cert := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}

	client := fakeClient(t)
	ar, err := client.AuthResultFromToken(ctx, mtlsPoPParams(cert), mtlsPoPToken())
	if err != nil {
		t.Fatal(err)
	}
	if ar.BindingCertificate == nil {
		t.Fatal("expected the binding certificate on the result")
	}
	if ar.BindingCertificate.Leaf == nil || !ar.BindingCertificate.Leaf.Equal(leaf) {
		t.Error("expected the result's binding certificate to carry the parsed leaf")
	}
	if ar.BindingCertificateThumbprint() == "" {
		t.Error("expected a thumbprint for a resolved binding certificate")
	}
	accounts, err := client.AllAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) == 0 {
		t.Error("a successful mTLS PoP acquisition should still be cached")
	}
}

// TestAcquireTokenSilentRequiresBindingCertificate covers the cache-read path, which had the same
// gap: a cache hit on an mTLS PoP token returned a result whose BindingCertificate was silently nil.
func TestAcquireTokenSilentRequiresBindingCertificate(t *testing.T) {
	ctx := context.Background()
	leaf, key := selfSignedCert(t)
	good := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key}

	client := fakeClient(t)
	if _, err := client.AuthResultFromToken(ctx, mtlsPoPParams(good), mtlsPoPToken()); err != nil {
		t.Fatal(err)
	}

	// Same token, now read back with a binding certificate that cannot be resolved.
	_, err := client.AcquireTokenSilent(ctx, AcquireTokenSilentParameters{
		Scopes:          testScopes,
		IsMtlsPoP:       true,
		MtlsBindingCert: &tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}},
	})
	if err == nil {
		t.Fatal("a cache hit returned an mTLS PoP result with no binding certificate to present")
	}
}

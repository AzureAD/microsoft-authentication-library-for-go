// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

func TestCertFromPEM(t *testing.T) {
	f, err := os.Open(filepath.Clean("../testdata/test-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pemData, err := ioutil.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	certs, key, err := CertFromPEM(pemData, "")
	if err != nil {
		t.Fatalf("TestCertFromPEM: got err == %s, want err == nil", err)
	}
	if len(certs) != 1 {
		t.Fatalf("TestCertFromPEM: got %d certs, want 1 cert", len(certs))
	}
	if key == nil {
		t.Fatalf("TestCertFromPEM: got nil key, want key != nil")
	}
}

const (
	token   = "fake_token"
	refresh = "fake_refresh"
)

var tokenScope = []string{"the_scope"}

func fakeClient(tk accesstokens.TokenResponse, credential Credential) (Client, error) {
	client, err := New("fake_client_id", credential, WithAuthority("https://fake_authority/fake"))
	if err != nil {
		return Client{}, err
	}
	client.base.Token.AccessTokens = &fake.AccessTokens{
		AccessToken: tk,
	}
	client.base.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			TenantDiscoveryEndpoint: "https://fake_authority/fake/discovery/endpoint",
			Metadata: []authority.InstanceDiscoveryMetadata{
				{
					PreferredNetwork: "fake_authority",
					PreferredCache:   "fake_cache",
					Aliases: []string{
						"fake_authority",
						"fake_auth",
						"fk_au",
					},
				},
			},
			AdditionalFields: map[string]interface{}{
				"api-version": "2020-02-02",
			},
		},
	}
	client.base.Token.Resolver = &fake.ResolveEndpoints{
		Endpoints: authority.NewEndpoints("https://fake_authority/fake/auth",
			"https://fake_authority/fake/token", "https://fake_authority/fake/jwt", "fake_authority"),
	}
	client.base.Token.WSTrust = &fake.WSTrust{}
	return client, nil
}

func TestAcquireTokenByCredential(t *testing.T) {
	tests := []struct {
		desc string
		cred string
	}{
		{
			desc: "Secret",
			cred: "fake_secret",
		},
		{
			desc: "Signed Assertion",
			cred: "fake_assertion",
		},
	}

	for _, test := range tests {
		cred, err := NewCredFromSecret(test.cred)
		if err != nil {
			t.Fatal(err)
		}
		client, err := fakeClient(accesstokens.TokenResponse{
			AccessToken:   token,
			ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
			ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
			GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		}, cred)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.AcquireTokenSilent(context.Background(), tokenScope)
		// first attempt should fail
		if err == nil {
			t.Errorf("TestAcquireTokenByCredential(%s): unexpected nil error from AcquireTokenSilent", test.desc)
		}
		tk, err := client.AcquireTokenByCredential(context.Background(), tokenScope)
		if err != nil {
			t.Errorf("TestAcquireTokenByCredential(%s): got err == %s, want err == nil", test.desc, err)
		}
		if tk.AccessToken != token {
			t.Errorf("TestAcquireTokenByCredential(%s): unexpected access token %s", test.desc, tk.AccessToken)
		}
		// second attempt should return the cached token
		tk, err = client.AcquireTokenSilent(context.Background(), tokenScope)
		if err != nil {
			t.Errorf("TestAcquireTokenByCredential(%s): got err == %s, want err == nil", test.desc, err)
		}
		if tk.AccessToken != token {
			t.Errorf("TestAcquireTokenByCredential(%s): unexpected access token %s", test.desc, tk.AccessToken)
		}
	}
}

func TestAcquireTokenByAssertionCallback(t *testing.T) {
	calls := 0
	ctx := context.WithValue(context.Background(), "test", true)
	getAssertion := func(c context.Context) (string, error) {
		if !c.Value("test").(bool) {
			t.Fatal("callback received unexpected context")
		}
		calls++
		if calls < 4 {
			return "assertion", nil
		}
		return "", errors.New("expected error")
	}
	cred := NewCredFromAssertionCallback(getAssertion)
	client, err := fakeClient(accesstokens.TokenResponse{}, cred)
	for i := 0; i < 3; i++ {
		if calls != i {
			t.Fatalf("expected %d calls, got %d", i, calls)
		}
		_, err = client.AcquireTokenByCredential(ctx, tokenScope)
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = client.AcquireTokenByCredential(ctx, tokenScope)
	if err == nil || err.Error() != "expected error" {
		t.Fatalf("expected an error from the callback, got %v", err)
	}
}

func TestAcquireTokenByAuthCode(t *testing.T) {
	cred, err := NewCredFromSecret("fake_secret")
	if err != nil {
		t.Fatal(err)
	}
	client, err := fakeClient(accesstokens.TokenResponse{
		AccessToken:   token,
		RefreshToken:  refresh,
		ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		IDToken: accesstokens.IDToken{
			PreferredUsername: "fakeuser@fakeplace.fake",
			Name:              "fake person",
			Oid:               "123-456",
			TenantID:          "fake",
			Subject:           "nothing",
			Issuer:            "https://fake_authority/fake",
			Audience:          "abc-123",
			ExpirationTime:    time.Now().Add(time.Hour).Unix(),
			IssuedAt:          time.Now().Add(-5 * time.Minute).Unix(),
			NotBefore:         time.Now().Add(-5 * time.Minute).Unix(),
			// NOTE: this is an invalid JWT however this doesn't cause a failure.
			// it simply falls back to calling Token.Refresh() which will obviously succeed.
			RawToken: "fake.raw.token",
		},
		ClientInfo: accesstokens.ClientInfo{
			UID:  "123-456",
			UTID: "fake",
		},
	}, cred)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.AcquireTokenSilent(context.Background(), tokenScope)
	// first attempt should fail
	if err == nil {
		t.Fatal("unexpected nil error from AcquireTokenSilent")
	}
	tk, err := client.AcquireTokenByAuthCode(context.Background(), "fake_auth_code", "fake_redirect_uri", tokenScope)
	if err != nil {
		t.Fatal(err)
	}
	if tk.AccessToken != token {
		t.Fatalf("unexpected access token %s", tk.AccessToken)
	}
	account := client.Account(tk.Account.HomeAccountID)
	// second attempt should return the cached token
	tk, err = client.AcquireTokenSilent(context.Background(), tokenScope, WithSilentAccount(account))
	if err != nil {
		t.Fatal(err)
	}
	if tk.AccessToken != token {
		t.Fatalf("unexpected access token %s", tk.AccessToken)
	}
}

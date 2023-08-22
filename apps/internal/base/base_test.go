// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package base

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/internal/storage"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	"github.com/kylelemons/godebug/pretty"
)

const (
	fakeAccessToken  = "fake-access-token"
	fakeAuthority    = "fake_authority"
	fakeClientID     = "fake-client-id"
	fakeRefreshToken = "fake-refresh-token"
	fakeTenantID     = "fake-tenant-id"
	fakeUsername     = "fake-username"
)

var (
	fakeIDToken = accesstokens.IDToken{
		Oid:               "oid",
		PreferredUsername: fakeUsername,
		RawToken:          "x.e30",
		TenantID:          fakeTenantID,
		UPN:               fakeUsername,
	}
	testScopes = []string{"scope"}
)

func fakeClient(t *testing.T, opts ...Option) Client {
	client, err := New(fakeClientID, fmt.Sprintf("https://%s/%s", fakeAuthority, fakeTenantID), &oauth.Client{}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	client.Token.AccessTokens = &fake.AccessTokens{
		AccessToken: accesstokens.TokenResponse{
			AccessToken:   fakeAccessToken,
			ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(time.Hour)},
			FamilyID:      "family-id",
			GrantedScopes: accesstokens.Scopes{Slice: testScopes},
			IDToken:       fakeIDToken,
			RefreshToken:  fakeRefreshToken,
		},
	}
	client.Token.Authority = &fake.Authority{
		InstanceResp: authority.InstanceDiscoveryResponse{
			Metadata: []authority.InstanceDiscoveryMetadata{
				{Aliases: []string{fakeAuthority}, PreferredNetwork: fakeAuthority},
			},
			TenantDiscoveryEndpoint: fmt.Sprintf("https://%s/fake/discovery/endpoint", fakeAuthority),
		},
	}
	client.Token.Resolver = &fake.ResolveEndpoints{
		Endpoints: authority.NewEndpoints(
			fmt.Sprintf("https://%s/fake/auth", fakeAuthority),
			fmt.Sprintf("https://%s/fake/token", fakeAuthority),
			fmt.Sprintf("https://%s/fake/jwt", fakeAuthority),
			fakeAuthority,
		),
	}
	return client
}

func TestAcquireTokenSilentEmptyCache(t *testing.T) {
	client := fakeClient(t)
	_, err := client.AcquireTokenSilent(context.Background(), AcquireTokenSilentParameters{
		Account: shared.NewAccount("homeAccountID", "env", "realm", "localAccountID", authority.AAD, "username"),
		Scopes:  testScopes,
	})
	if err == nil {
		t.Fatal("expected an error because the cache is empty")
	}
}

func TestAcquireTokenSilentScopes(t *testing.T) {
	// ensure fakeIDToken.RawToken unmarshals (doesn't matter to what) because an unmarshalling
	// error can conceal a test bug by making an "err != nil" check true for the wrong reason
	var idToken accesstokens.IDToken
	if err := idToken.UnmarshalJSON([]byte(fakeIDToken.RawToken)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		desc              string
		cachedTokenScopes []string
	}{
		{"expired access token", testScopes},
		{"no access token", []string{"other-" + testScopes[0]}},
	} {
		t.Run(test.desc, func(t *testing.T) {
			client := fakeClient(t)
			validated := false
			client.Token.AccessTokens.(*fake.AccessTokens).FromRefreshTokenCallback = func(at accesstokens.AppType, ap authority.AuthParams, cc *accesstokens.Credential, rt string) {
				validated = true
				if !reflect.DeepEqual(ap.Scopes, testScopes) {
					t.Fatalf("unexpected scopes: %v", ap.Scopes)
				}
				if cc != nil {
					t.Fatal("client shouldn't have a credential")
				}
				if rt != fakeRefreshToken {
					t.Fatal("unexpected refresh token")
				}
			}

			// cache a refresh token and an expired access token for the given scopes
			// (testing only the public client code path)
			storage.FakeValidate = func(storage.AccessToken) error { return nil }
			account, err := client.manager.Write(
				authority.AuthParams{
					AuthorityInfo: authority.Info{
						AuthorityType: authority.AAD,
						Host:          fakeAuthority,
						Tenant:        fakeIDToken.TenantID,
					},
					ClientID:    fakeClientID,
					Scopes:      test.cachedTokenScopes,
					Username:    fakeIDToken.PreferredUsername,
					AuthnScheme: &authority.BearerAuthenticationScheme{},
				},
				accesstokens.TokenResponse{
					AccessToken:   fakeAccessToken,
					ClientInfo:    accesstokens.ClientInfo{UID: "uid", UTID: "utid"},
					ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(-time.Hour)},
					GrantedScopes: accesstokens.Scopes{Slice: test.cachedTokenScopes},
					IDToken:       fakeIDToken,
					RefreshToken:  fakeRefreshToken,
				},
			)
			storage.FakeValidate = nil
			if err != nil {
				t.Fatal(err)
			}

			// AcquireTokenSilent should redeem the refresh token for a new access token
			ar, err := client.AcquireTokenSilent(context.Background(), AcquireTokenSilentParameters{Account: account, Scopes: testScopes})
			if err != nil {
				t.Fatal(err)
			}
			if ar.AccessToken != fakeAccessToken {
				t.Fatal("unexpected access token")
			}
			if !validated {
				t.Fatal("FromRefreshTokenCallback wasn't called")
			}
		})
	}
}

func TestAcquireTokenSilentGrantedScopes(t *testing.T) {
	client := fakeClient(t)
	grantedScopes := []string{"scope1", "scope2"}
	expectedToken := "not-" + fakeAccessToken
	account, err := client.manager.Write(
		authority.AuthParams{
			AuthorityInfo: authority.Info{
				AuthorityType: authority.AAD,
				Host:          fakeAuthority,
				Tenant:        fakeIDToken.TenantID,
			},
			ClientID:    fakeClientID,
			Scopes:      grantedScopes[1:],
			AuthnScheme: &authority.BearerAuthenticationScheme{},
		},
		accesstokens.TokenResponse{
			AccessToken:   expectedToken,
			ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(time.Hour)},
			GrantedScopes: accesstokens.Scopes{Slice: grantedScopes},
			TokenType:     "Bearer",
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, scope := range grantedScopes {
		ar, err := client.AcquireTokenSilent(context.Background(), AcquireTokenSilentParameters{Account: account, Scopes: []string{scope}})
		if err != nil {
			t.Fatal(err)
		}
		if ar.AccessToken != expectedToken {
			t.Fatal("unexpected access token")
		}
	}
}

// failCache helps tests inject cache I/O errors
type failCache struct {
	exported              bool
	exportErr, replaceErr error
}

func (c *failCache) Export(context.Context, cache.Marshaler, cache.ExportHints) error {
	c.exported = true
	return c.exportErr
}

func (c failCache) Replace(context.Context, cache.Unmarshaler, cache.ReplaceHints) error {
	return c.replaceErr
}

func TestCacheIOErrors(t *testing.T) {
	ctx := context.Background()
	expected := errors.New("cache error")
	for _, export := range []bool{true, false} {
		name := "replace"
		cache := failCache{}
		if export {
			cache.exportErr = expected
			name = "export"
		} else {
			cache.replaceErr = expected
		}
		t.Run(name, func(t *testing.T) {
			client := fakeClient(t, WithCacheAccessor(&cache))
			if !export {
				// Account and AllAccounts don't export the cache, and AcquireTokenSilent does so
				// only after redeeming a refresh token, so we test them only for replace errors
				_, actual := client.Account(ctx, "...")
				if !errors.Is(actual, expected) {
					t.Fatalf(`expected "%v", got "%v"`, expected, actual)
				}
				_, actual = client.AllAccounts(ctx)
				if !errors.Is(actual, expected) {
					t.Fatalf(`expected "%v", got "%v"`, expected, actual)
				}
				_, actual = client.AcquireTokenSilent(ctx, AcquireTokenSilentParameters{Scopes: testScopes})
				if cache.replaceErr != nil && !errors.Is(actual, expected) {
					t.Fatalf(`expected "%v", got "%v"`, expected, actual)
				}
			}
			_, actual := client.AcquireTokenByAuthCode(ctx, AcquireTokenAuthCodeParameters{AppType: accesstokens.ATConfidential, Scopes: testScopes})
			if !errors.Is(actual, expected) {
				t.Fatalf(`expected "%v", got "%v"`, expected, actual)
			}
			_, actual = client.AcquireTokenOnBehalfOf(ctx, AcquireTokenOnBehalfOfParameters{Credential: &accesstokens.Credential{Secret: "..."}, Scopes: testScopes})
			if !errors.Is(actual, expected) {
				t.Fatalf(`expected "%v", got "%v"`, expected, actual)
			}
			_, actual = client.AuthResultFromToken(ctx, authority.AuthParams{AuthnScheme: &authority.BearerAuthenticationScheme{}}, accesstokens.TokenResponse{}, true)
			if !errors.Is(actual, expected) {
				t.Fatalf(`expected "%v", got "%v"`, expected, actual)
			}
			actual = client.RemoveAccount(ctx, shared.Account{})
			if !errors.Is(actual, expected) {
				t.Fatalf(`expected "%v", got "%v"`, expected, actual)
			}
		})
	}

	// testing that AcquireTokenSilent propagates errors from Export requires more elaborate
	// setup because that method exports the cache only after acquiring a new access token
	t.Run("silent auth export error", func(t *testing.T) {
		cache := failCache{}
		hid := "uid.utid"
		client := fakeClient(t, WithCacheAccessor(&cache))
		// cache fake tokens and app metadata
		_, err := client.AuthResultFromToken(ctx,
			authority.AuthParams{
				AuthorityInfo: authority.Info{Host: fakeAuthority},
				ClientID:      fakeClientID,
				HomeAccountID: hid,
				Scopes:        testScopes,
				AuthnScheme:   &authority.BearerAuthenticationScheme{},
			},
			accesstokens.TokenResponse{
				AccessToken:   "at",
				ClientInfo:    accesstokens.ClientInfo{UID: "uid", UTID: "utid"},
				GrantedScopes: accesstokens.Scopes{Slice: testScopes},
				IDToken:       fakeIDToken,
				RefreshToken:  "rt",
			},
			true,
		)
		if err != nil {
			t.Fatal(err)
		}
		// AcquireTokenSilent should return this error after redeeming a refresh token
		cache.exportErr = expected
		_, actual := client.AcquireTokenSilent(ctx,
			AcquireTokenSilentParameters{
				Account: shared.NewAccount(hid, fakeAuthority, "realm", "id", authority.AAD, "upn"),
				Scopes:  []string{"not-" + testScopes[0]},
			},
		)
		if !errors.Is(actual, expected) {
			t.Fatalf(`expected "%v", got "%v"`, expected, actual)
		}
	})

	// when the client fails to acquire a token, it should return an error instead of exporting the cache
	t.Run("auth error", func(t *testing.T) {
		cache := failCache{}
		client := fakeClient(t, WithCacheAccessor(&cache))
		client.Token.AccessTokens.(*fake.AccessTokens).Err = true
		_, err := client.AcquireTokenByAuthCode(ctx, AcquireTokenAuthCodeParameters{AppType: accesstokens.ATConfidential})
		if err == nil || cache.exported {
			t.Fatal("client should have returned an error instead of exporting the cache")
		}
		_, err = client.AcquireTokenOnBehalfOf(ctx, AcquireTokenOnBehalfOfParameters{Credential: &accesstokens.Credential{Secret: "..."}})
		if err == nil || cache.exported {
			t.Fatal("client should have returned an error instead of exporting the cache")
		}
		_, err = client.AcquireTokenSilent(ctx, AcquireTokenSilentParameters{})
		if err == nil || cache.exported {
			t.Fatal("client should have returned an error instead of exporting the cache")
		}
	})
}

func TestCreateAuthenticationResult(t *testing.T) {
	future := time.Now().Add(400 * time.Second)

	tests := []struct {
		desc  string
		input accesstokens.TokenResponse
		want  AuthResult
		err   bool
	}{
		{
			desc: "no declined scopes",
			input: accesstokens.TokenResponse{
				AccessToken:    "accessToken",
				ExpiresOn:      internalTime.DurationTime{T: future},
				GrantedScopes:  accesstokens.Scopes{Slice: []string{"user.read"}},
				DeclinedScopes: nil,
			},
			want: AuthResult{
				AccessToken:    "accessToken",
				ExpiresOn:      future,
				GrantedScopes:  []string{"user.read"},
				DeclinedScopes: nil,
			},
		},
		{
			desc: "declined scopes",
			input: accesstokens.TokenResponse{
				AccessToken:    "accessToken",
				ExpiresOn:      internalTime.DurationTime{T: future},
				GrantedScopes:  accesstokens.Scopes{Slice: []string{"user.read"}},
				DeclinedScopes: []string{"openid"},
			},
			err: true,
		},
	}

	for _, test := range tests {
		got, err := NewAuthResult(test.input, shared.Account{})
		switch {
		case err == nil && test.err:
			t.Errorf("TestCreateAuthenticationResult(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestCreateAuthenticationResult(%s): got err == %s, want err == nil", test.desc, err)
		case err != nil:
			continue
		}

		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestCreateAuthenticationResult(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}

func TestAuthResultFromStorage(t *testing.T) {
	now := time.Now()
	future := time.Now().Add(500 * time.Second)

	tests := []struct {
		desc       string
		storeToken storage.TokenResponse
		want       AuthResult
		err        bool
	}{
		{
			desc: "Error: AccessToken.Validate error (AccessToken.CachedAt not set)",
			storeToken: storage.TokenResponse{
				AccessToken: storage.AccessToken{
					ExpiresOn: internalTime.Unix{T: future},
					Secret:    "secret",
					Scopes:    "profile openid user.read",
				},
				IDToken: storage.IDToken{Secret: "x.e30"},
			},
			err: true,
		},
		{
			desc: "Success",
			storeToken: storage.TokenResponse{
				AccessToken: storage.AccessToken{
					CachedAt:  internalTime.Unix{T: now},
					ExpiresOn: internalTime.Unix{T: future},
					Secret:    "secret",
					Scopes:    "profile openid user.read",
				},
				IDToken: storage.IDToken{Secret: "x.e30"},
			},
			want: AuthResult{
				AccessToken: "secret",
				IDToken: accesstokens.IDToken{
					RawToken: "x.e30",
				},
				ExpiresOn:     future,
				GrantedScopes: []string{"profile", "openid", "user.read"},
			},
		},
	}

	for _, test := range tests {
		got, err := AuthResultFromStorage(test.storeToken)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAuthResultFromStorage(%s): got err == nil, want == != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAuthResultFromStorage(%s): got err == %s, want == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := (&pretty.Config{IncludeUnexported: false}).Compare(test.want, got); diff != "" {
			t.Errorf("TestAuthResultFromStorage: -want/+got:\n%s", diff)
		}
	}
}

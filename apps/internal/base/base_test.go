// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package base

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

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

func fakeClient(t *testing.T) Client {
	client, err := New(fakeClientID, fmt.Sprintf("https://%s/%s", fakeAuthority, fakeTenantID), &oauth.Client{})
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
					ClientID: fakeClientID,
					Scopes:   test.cachedTokenScopes,
					Username: fakeIDToken.PreferredUsername,
				},
				accesstokens.TokenResponse{
					AccessToken:   fakeAccessToken,
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

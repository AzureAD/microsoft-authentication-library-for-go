// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package base

import (
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/internal/storage"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"

	"github.com/kylelemons/godebug/pretty"
)

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

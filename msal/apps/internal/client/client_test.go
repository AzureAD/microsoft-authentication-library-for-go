package client

import (
	"strconv"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/client/internal/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/msalbase"

	"github.com/kylelemons/godebug/pretty"
)

func TestCreateAuthenticationResult(t *testing.T) {
	future := time.Now().Add(400 * time.Second)

	tests := []struct {
		desc  string
		input msalbase.TokenResponse
		want  AuthenticationResult
		err   bool
	}{
		{
			desc: "no declined scopes",
			input: msalbase.TokenResponse{
				AccessToken:    "accessToken",
				ExpiresOn:      future,
				GrantedScopes:  []string{"user.read"},
				DeclinedScopes: nil,
			},
			want: AuthenticationResult{
				AccessToken:    "accessToken",
				ExpiresOn:      future,
				GrantedScopes:  []string{"user.read"},
				DeclinedScopes: nil,
			},
		},
		{
			desc: "declined scopes",
			input: msalbase.TokenResponse{
				AccessToken:    "accessToken",
				ExpiresOn:      future,
				GrantedScopes:  []string{"user.read"},
				DeclinedScopes: []string{"openid"},
			},
			err: true,
		},
	}

	for _, test := range tests {
		got, err := CreateAuthenticationResult(test.input, msalbase.Account{})
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

func TestCreateAuthenticationResultFromStorageTokenResponse(t *testing.T) {
	now := time.Now()
	future := time.Now().Add(500 * time.Second)

	tests := []struct {
		desc       string
		storeToken storage.StorageTokenResponse
		want       AuthenticationResult
		err        bool
	}{
		{
			desc: "Error: AccessToken.Validate error (AccessToken.CachedAt not set)",
			storeToken: storage.StorageTokenResponse{
				AccessToken: storage.AccessToken{
					ExpiresOnUnixTimestamp: strconv.FormatInt(future.Unix(), 10),
					Secret:                 "secret",
					Scopes:                 "profile openid user.read",
				},
				IDToken: storage.IDToken{Secret: "x.e30"},
			},
			err: true,
		},
		{
			desc: "Success",
			storeToken: storage.StorageTokenResponse{
				AccessToken: storage.AccessToken{
					CachedAt:               strconv.FormatInt(now.Unix(), 10),
					ExpiresOnUnixTimestamp: strconv.FormatInt(future.Unix(), 10),
					Secret:                 "secret",
					Scopes:                 "profile openid user.read",
				},
				IDToken: storage.IDToken{Secret: "x.e30"},
			},
			want: AuthenticationResult{
				AccessToken: "secret",
				IDToken: msalbase.IDToken{
					RawToken: "x.e30",
				},
				ExpiresOn:     future,
				GrantedScopes: []string{"profile", "openid", "user.read"},
			},
		},
	}

	for _, test := range tests {
		got, err := CreateAuthenticationResultFromStorageTokenResponse(test.storeToken)
		switch {
		case err == nil && test.err:
			t.Errorf("TestCreateAuthenticationResultFromStorageTokenResponse(%s): got err == nil, want == != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestCreateAuthenticationResultFromStorageTokenResponse(%s): got err == %s, want == == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := (&pretty.Config{IncludeUnexported: false}).Compare(test.want, got); diff != "" {
			t.Errorf("TestCreateAuthenticationResultFromStorageTokenResponse: -want/+got:\n%s", diff)
		}
	}
}

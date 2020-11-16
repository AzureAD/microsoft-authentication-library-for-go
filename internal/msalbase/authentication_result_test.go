// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"reflect"
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
)

func TestCreateAuthenticationResult(t *testing.T) {
	testAccessToken := "accessToken"
	testExpiresOn := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	testIDToken := IDToken{}
	testGrantedScopes := []string{"user.read"}
	testDeclinedScopesWithoutError := []string{}
	testDeclinedScopesWithError := []string{"openid"}

	tests := []struct {
		desc  string
		input TokenResponse
		want  AuthenticationResult
		err   bool
	}{
		{
			desc: "no declined scopes",
			input: TokenResponse{
				AccessToken:    testAccessToken,
				ExpiresOn:      testExpiresOn,
				IDToken:        testIDToken,
				GrantedScopes:  testGrantedScopes,
				declinedScopes: testDeclinedScopesWithoutError,
			},
			want: AuthenticationResult{
				Account:        Account{},
				idToken:        testIDToken,
				AccessToken:    testAccessToken,
				ExpiresOn:      testExpiresOn,
				GrantedScopes:  testGrantedScopes,
				DeclinedScopes: nil,
			},
		},
		{
			desc: "declined scopes",
			input: TokenResponse{
				AccessToken:    testAccessToken,
				ExpiresOn:      testExpiresOn,
				IDToken:        testIDToken,
				GrantedScopes:  testGrantedScopes,
				declinedScopes: testDeclinedScopesWithError,
			},
			err: true,
		},
	}

	for _, test := range tests {
		got, err := CreateAuthenticationResult(test.input, Account{})
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
	at := new(MockAccessToken)
	id := new(MockCredential)
	acc := Account{}
	atSecret := "secret"
	storageToken := StorageTokenResponse{
		AccessToken: at,
		IDToken:     id,
		account:     acc,
	}
	at.On("GetSecret").Return(atSecret)
	at.On("GetExpiresOn").Return("1592049600")
	at.On("GetScopes").Return("profile openid user.read")
	id.On("GetSecret").Return("x.e30")
	expAuthResult := AuthenticationResult{
		Account:       acc,
		AccessToken:   atSecret,
		idToken:       IDToken{},
		ExpiresOn:     time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC),
		GrantedScopes: []string{"profile", "openid", "user.read"},
	}
	actualAuthResult, err := CreateAuthenticationResultFromStorageTokenResponse(storageToken)
	if err != nil {
		t.Errorf("Error should be nil but it is %v", err)
	}
	if !reflect.DeepEqual(actualAuthResult.Account, acc) &&
		!reflect.DeepEqual(actualAuthResult.AccessToken, atSecret) &&
		!reflect.DeepEqual(actualAuthResult.idToken, &IDToken{}) &&
		!reflect.DeepEqual(actualAuthResult.ExpiresOn, time.Date(2020, time.June, 13, 12, 0, 0, 0, time.UTC)) &&
		!reflect.DeepEqual(actualAuthResult.GrantedScopes, []string{"profile", "openid", "user.read"}) {
		t.Errorf("Actual authentication result %+v differs from expected authentication result %+v", actualAuthResult, expAuthResult)
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
	"reflect"
	"time"
)

// AuthenticationResult contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type AuthenticationResult struct {
	Account        *Account
	idToken        *IDToken
	AccessToken    string
	ExpiresOn      time.Time
	GrantedScopes  []string
	DeclinedScopes []string
}

func CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse *StorageTokenResponse) (*AuthenticationResult, error) {
	if storageTokenResponse == nil {
		return nil, errors.New("storage token response is nil")
	}
	account := storageTokenResponse.account
	var idToken *IDToken
	accessToken := ""
	var expiresOn time.Time
	grantedScopes := []string{}
	declinedScopes := []string{}
	var err error
	if !reflect.ValueOf(storageTokenResponse.accessToken).IsNil() {
		accessToken = storageTokenResponse.accessToken.GetSecret()
		expiresOn, err = ConvertStrUnixToUTCTime(storageTokenResponse.accessToken.GetExpiresOn())
		if err != nil {
			return nil, errors.New("access token in cache expires at an invalid time")
		}
		grantedScopes = SplitScopes(storageTokenResponse.accessToken.GetScopes())
	} else {
		return nil, errors.New("no access token present in cache")
	}

	if !reflect.ValueOf(storageTokenResponse.idToken).IsNil() {
		idToken, err = CreateIDToken(storageTokenResponse.idToken.GetSecret())
		if err != nil {
			return nil, err
		}
	}

	ar := &AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, declinedScopes}
	return ar, nil
}

// CreateAuthenticationResult creates and AuthenticationResult.  This should only be called from internal code.
func CreateAuthenticationResult(tokenResponse *TokenResponse, account *Account) (*AuthenticationResult, error) {
	grantedScopes := tokenResponse.GrantedScopes
	declinedScopes := tokenResponse.declinedScopes
	if len(declinedScopes) > 0 {
		return nil, errors.New("token response failed because declined scopes are present")
	}

	idToken := tokenResponse.IDToken
	accessToken := tokenResponse.AccessToken
	expiresOn := tokenResponse.ExpiresOn

	ar := &AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, declinedScopes}
	return ar, nil
}

func (ar *AuthenticationResult) GetAccessToken() string {
	if ar == nil {
		return ""
	} else {
		return ar.AccessToken
	}
}

func (ar *AuthenticationResult) GetAccount() *Account {
	if ar == nil {
		return nil
	} else {
		return ar.Account
	}
}

func (ar *AuthenticationResult) GetIdToken() string {
	if ar == nil || ar.idToken == nil {
		return ""
	}
	return ar.idToken.RawToken
}

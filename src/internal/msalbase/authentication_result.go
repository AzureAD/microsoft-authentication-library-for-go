// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
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
	account := storageTokenResponse.account
	var idToken *IDToken
	accessToken := ""
	expiresOn := time.Now()
	grantedScopes := []string{}
	declinedScopes := []string{}
	var err error

	if storageTokenResponse.accessToken != nil {
		accessToken = storageTokenResponse.accessToken.GetSecret()
		expiresOn, err = ConvertStrUnixToUTCTime(storageTokenResponse.accessToken.GetExpiresOn())
		if err != nil {
			return nil, err
		}
		grantedScopes = SplitScopes(storageTokenResponse.accessToken.GetScopes())
	} else {
		return nil, errors.New("No access token present")
	}

	if storageTokenResponse.idToken != nil {
		idToken, err = CreateIDToken(storageTokenResponse.idToken.GetSecret())
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("No ID token present")
	}

	ar := &AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, declinedScopes}
	return ar, nil
}

// CreateAuthenticationResult creates and AuthenticationResult.  This should only be called from internal code.
func CreateAuthenticationResult(tokenResponse *TokenResponse, account *Account) (*AuthenticationResult, error) {
	grantedScopes := tokenResponse.GrantedScopes
	declinedScopes := tokenResponse.declinedScopes
	if len(declinedScopes) > 0 {
		return nil, errors.New("Token response failed because declined scopes are present")

	}

	idToken := tokenResponse.IDToken
	accessToken := tokenResponse.AccessToken
	expiresOn := tokenResponse.ExpiresOn

	ar := &AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, declinedScopes}
	return ar, nil
}

func (ar *AuthenticationResult) GetAccessToken() string {
	return ar.AccessToken
}

func (ar *AuthenticationResult) GetAccount() *Account {
	return ar.Account
}

func (ar *AuthenticationResult) GetIdToken() string {
	if ar.idToken == nil {
		return ""
	}
	return ar.idToken.RawToken
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
	"strings"
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

	var account *Account
	var idToken *IDToken
	accessToken := ""
	expiresOn := time.Now()
	grantedScopes := []string{}
	declinedScopes := []string{}
	var err error

	if storageTokenResponse.accessToken != nil {
		accessToken = storageTokenResponse.accessToken.GetSecret()
		expiresOn = time.Unix(storageTokenResponse.accessToken.GetExpiresOn(), 0)
		grantedScopes = strings.Split(storageTokenResponse.accessToken.GetScopes(), " ")
	}

	if storageTokenResponse.idToken != nil {
		idToken, err = CreateIDToken(storageTokenResponse.idToken.GetSecret())
		if err != nil {
			return nil, err
		}
	} else {
		idToken, err = CreateIDToken("")
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

func (ar *AuthenticationResult) GetIdToken() string {
	if ar.idToken == nil {
		return ""
	}

	return ar.idToken.GetRaw()
}

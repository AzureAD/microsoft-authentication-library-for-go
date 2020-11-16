// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// AuthenticationResult contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type AuthenticationResult struct {
	Account        Account
	idToken        IDToken
	AccessToken    string
	ExpiresOn      time.Time
	GrantedScopes  []string
	DeclinedScopes []string
}

// CreateAuthenticationResultFromStorageTokenResponse creates an authenication result from a storage token response (which is generated from the cache).
func CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse StorageTokenResponse) (AuthenticationResult, error) {
	if storageTokenResponse.AccessToken == nil {
		return AuthenticationResult{}, errors.New("no access token present in cache")
	}

	account := storageTokenResponse.account
	accessToken := storageTokenResponse.AccessToken.GetSecret()
	expiresOn, err := ConvertStrUnixToUTCTime(storageTokenResponse.AccessToken.GetExpiresOn())
	if err != nil {
		return AuthenticationResult{},
			fmt.Errorf("token response from server is invalid because expires_in is set to %q", storageTokenResponse.AccessToken.GetExpiresOn())
	}
	grantedScopes := SplitScopes(storageTokenResponse.AccessToken.GetScopes())

	// Checking if there was an ID token in the cache; this will throw an error in the case of confidential client applications.
	var idToken IDToken
	if storageTokenResponse.IDToken != nil {
		idToken, err = CreateIDToken(storageTokenResponse.IDToken.GetSecret())
		if err != nil {
			return AuthenticationResult{}, err
		}
	}
	return AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, nil}, nil
}

// CreateAuthenticationResult creates an AuthenticationResult.
// TODO(jdoak): Make this a method on TokenResponse() that takes only 1 arge, Account.
func CreateAuthenticationResult(tokenResponse TokenResponse, account Account) (AuthenticationResult, error) {
	if len(tokenResponse.declinedScopes) > 0 {
		return AuthenticationResult{}, fmt.Errorf("token response failed because declined scopes are present: %s", strings.Join(tokenResponse.declinedScopes, ","))
	}
	return AuthenticationResult{
		Account:       account,
		idToken:       tokenResponse.IDToken,
		AccessToken:   tokenResponse.AccessToken,
		ExpiresOn:     tokenResponse.ExpiresOn,
		GrantedScopes: tokenResponse.GrantedScopes,
	}, nil
}

//GetAccessToken returns the access token of the authentication result
func (ar AuthenticationResult) GetAccessToken() string {
	return ar.AccessToken
}

// GetAccount returns the account of the authentication result
func (ar AuthenticationResult) GetAccount() Account {
	return ar.Account
}

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

//CreateAuthenticationResultFromStorageTokenResponse creates an authenication result from a storage token response (which is generated from the cache)
func CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse *StorageTokenResponse) (*AuthenticationResult, error) {
	if storageTokenResponse == nil {
		return nil, errors.New("Storage token response is nil")
	}
	account := storageTokenResponse.account
	var idToken *IDToken
	accessToken := ""
	var expiresOn time.Time
	grantedScopes := []string{}
	declinedScopes := []string{}
	var err error
	// Checking if the cache had an access token, if not, need to throw an error
	if !reflect.ValueOf(storageTokenResponse.accessToken).IsNil() {
		accessToken = storageTokenResponse.accessToken.GetSecret()
		expiresOn, err = ConvertStrUnixToUTCTime(storageTokenResponse.accessToken.GetExpiresOn())
		if err != nil {
			return nil, errors.New("Access token in cache expires at an invalid time")
		}
		grantedScopes = SplitScopes(storageTokenResponse.accessToken.GetScopes())
	} else {
		return nil, errors.New("No access token present in cache")
	}
	// Checking if there was an ID token in the cache; this will throw an error in the case of confidential client applications
	if !reflect.ValueOf(storageTokenResponse.idToken).IsNil() {
		idToken, err = CreateIDToken(storageTokenResponse.idToken.GetSecret())
		if err != nil {
			return nil, err
		}
	}
	ar := &AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, declinedScopes}
	return ar, nil
}

// CreateAuthenticationResult creates an AuthenticationResult
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

//GetAccessToken returns the access token of the authentication result
func (ar *AuthenticationResult) GetAccessToken() string {
	if ar == nil {
		return ""
	}
	return ar.AccessToken
}

//GetAccount returns the account of the authentication result
func (ar *AuthenticationResult) GetAccount() *Account {
	if ar == nil {
		return nil
	}
	return ar.Account
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

type tokenResponseJSONPayload struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	Foci         string `json:"foci"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	ClientInfo   string `json:"client_info"`
}

//ClientInfoJSONPayload is used to create a Home Account ID for an account
type ClientInfoJSONPayload struct {
	UID  string `json:"uid"`
	Utid string `json:"utid"`
}

//TokenResponse is the information that is returned from a token endpoint during a token acquisition flow
type TokenResponse struct {
	baseResponse   *OAuthResponseBase
	AccessToken    string
	RefreshToken   string
	IDToken        *IDToken
	FamilyID       string
	GrantedScopes  []string
	declinedScopes []string
	ExpiresOn      time.Time
	ExtExpiresOn   time.Time
	rawClientInfo  string
	ClientInfo     *ClientInfoJSONPayload
}

//HasAccessToken checks if the TokenResponse has an access token secret
func (tr *TokenResponse) HasAccessToken() bool {
	return len(tr.AccessToken) > 0
}

//HasRefreshToken checks if the TokenResponse has an refresh token secret
func (tr *TokenResponse) HasRefreshToken() bool {
	return len(tr.RefreshToken) > 0
}

//GetHomeAccountIDFromClientInfo creates the home account ID for an account from the client info parameter
func (tr *TokenResponse) GetHomeAccountIDFromClientInfo() string {
	if tr.ClientInfo.UID == "" || tr.ClientInfo.Utid == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", tr.ClientInfo.UID, tr.ClientInfo.Utid)
}

//CreateTokenResponse creates a TokenResponse instance from the response from the token endpoint
func CreateTokenResponse(authParameters *AuthParametersInternal, responseCode int, responseData string) (*TokenResponse, error) {
	baseResponse, err := CreateOAuthResponseBase(responseCode, responseData)
	if err != nil {
		return nil, err
	}
	payload := &tokenResponseJSONPayload{}
	err = json.Unmarshal([]byte(responseData), payload)
	if err != nil {
		return nil, err
	}

	if payload.AccessToken == "" {
		// Access token is required in a token response
		return nil, errors.New("response is missing access_token")
	}

	rawClientInfo := payload.ClientInfo
	clientInfo := &ClientInfoJSONPayload{}
	// Client info may be empty in some flows, e.g. certificate exchange.
	if len(rawClientInfo) > 0 {
		rawClientInfoDecoded, err := DecodeJWT(rawClientInfo)
		if err != nil {
			return nil, err
		}

		err = json.Unmarshal(rawClientInfoDecoded, clientInfo)
		if err != nil {
			return nil, err
		}
	}

	expiresOn := time.Now().Add(time.Second * time.Duration(payload.ExpiresIn))
	extExpiresOn := time.Now().Add(time.Second * time.Duration(payload.ExtExpiresIn))

	grantedScopes := []string{}
	declinedScopes := []string{}

	if len(payload.Scope) == 0 {
		// Per OAuth spec, if no scopes are returned, the response should be treated as if all scopes were granted
		// This behavior can be observed in client assertion flows, but can happen at any time, this check ensures we treat
		// those special responses properly
		// Link to spec: https://tools.ietf.org/html/rfc6749#section-3.3
		grantedScopes = authParameters.Scopes
	} else {
		grantedScopes = SplitScopes(payload.Scope)
		declinedScopes = findDeclinedScopes(authParameters.Scopes, grantedScopes)
	}

	idToken, err := CreateIDToken(payload.IDToken)
	if err != nil {
		//ID tokens aren't always returned, so the error is just logged
		log.Errorf("ID Token error: %v", err)
	}

	tokenResponse := &TokenResponse{
		baseResponse:   baseResponse,
		AccessToken:    payload.AccessToken,
		RefreshToken:   payload.RefreshToken,
		IDToken:        idToken,
		FamilyID:       payload.Foci,
		ExpiresOn:      expiresOn,
		ExtExpiresOn:   extExpiresOn,
		GrantedScopes:  grantedScopes,
		declinedScopes: declinedScopes,
		rawClientInfo:  rawClientInfo,
		ClientInfo:     clientInfo,
	}
	return tokenResponse, nil
}

func findDeclinedScopes(requestedScopes []string, grantedScopes []string) []string {
	declined := []string{}
	grantedMap := map[string]bool{}
	for _, s := range grantedScopes {
		grantedMap[s] = true
	}
	//Comparing the requested scopes with the granted scopes to see if there are any scopes that have been declined
	for _, r := range requestedScopes {
		if !grantedMap[r] {
			declined = append(declined, r)
		}
	}
	return declined
}

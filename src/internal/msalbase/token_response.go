// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
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

type clientInfoJSONPayload struct {
	UID  string `json:"uid"`
	Utid string `json:"utid"`
}

//TokenResponse
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
	clientInfo     *clientInfoJSONPayload
}

func (tr *TokenResponse) HasAccessToken() bool {
	return len(tr.AccessToken) > 0
}

func (tr *TokenResponse) HasRefreshToken() bool {
	return len(tr.RefreshToken) > 0
}

func (tr *TokenResponse) GetHomeAccountIDFromClientInfo() string {
	homeAccountID := tr.clientInfo.UID + "." + tr.clientInfo.Utid
	return homeAccountID
}

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
		// AccessToken is required, error out
		return nil, errors.New("response is missing access_token")
	}

	rawClientInfo := payload.ClientInfo
	clientInfo := &clientInfoJSONPayload{}

	// Client info may be empty in some flows, e.g. certificate exchange.
	if len(rawClientInfo) > 0 {
		// Adapted from MSAL Python and https://stackoverflow.com/a/31971780
		if i := len(rawClientInfo) % 4; i != 0 {
			rawClientInfo += strings.Repeat("=", 4-i)
		}
		rawClientInfoDecoded, err := base64.StdEncoding.DecodeString(rawClientInfo)
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
		return nil, err
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
		clientInfo:     clientInfo,
	}
	return tokenResponse, nil
}

func findDeclinedScopes(requestedScopes []string, grantedScopes []string) []string {
	declined := []string{}

	grantedMap := map[string]bool{}
	for _, s := range grantedScopes {
		grantedMap[s] = true
	}

	for _, r := range requestedScopes {
		if !grantedMap[r] {
			declined = append(declined, r)
		}
	}

	return declined
}

func CreateTokenResponseFromParts(idToken *IDToken, accessToken *Credential, refreshToken *Credential) (*TokenResponse, error) {
	/*
		var idt *IDToken
		accessTokenSecret := ""
		refreshTokenSecret := ""
		grantedScopes := []string{}

		if idToken != nil {
			idt = idToken
		} else {
			idt, _ = CreateIDToken("")
		}

		if accessToken != nil {
			accessTokenSecret = accessToken.GetSecret()
			// todo: fill this in...
			// _expiresOn = TimeUtils::ToTimePoint(accessToken->GetExpiresOn());
			// _extendedExpiresOn = TimeUtils::ToTimePoint(accessToken->GetExtendedExpiresOn());
			grantedScopes = strings.Split(accessToken.GetScopes(), " ")
		}

		if refreshToken != nil {
			refreshTokenSecret = refreshToken.GetSecret()
		}

		tokenResponse := &TokenResponse{
			IDToken:       idt,
			AccessToken:   accessTokenSecret,
			RefreshToken:  refreshTokenSecret,
			GrantedScopes: grantedScopes}
		return tokenResponse, nil*/
	return nil, nil
}

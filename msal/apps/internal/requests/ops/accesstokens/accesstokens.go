// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package accesstokens exposes a REST client for querying backend systems to get various types of
access tokens (oauth) for use in authentication.

These calls are of type "application/x-www-form-urlencoded".  This means we use url.Values to
represent arguments and then encode them into the POST body message.  We receive JSON in
return for the requests.  The request definition is defined in https://tools.ietf.org/html/rfc7521#section-4.2 .
*/
package accesstokens

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/requests/ops/wstrust"
)

const (
	grantType     = "grant_type"
	deviceCode    = "device_code"
	clientID      = "client_id"
	clientInfo    = "client_info"
	clientInfoVal = "1"
	username      = "username"
	password      = "password"
)

type urlFormCaller interface {
	URLFormCall(ctx context.Context, endpoint string, qv url.Values, resp interface{}) error
}

type createTokenResp func(authParameters msalbase.AuthParametersInternal, payload msalbase.TokenResponseJSONPayload) (msalbase.TokenResponse, error)

// DeviceCodeResponse represents the HTTP response received from the device code endpoint
type DeviceCodeResponse struct {
	msalbase.OAuthResponseBase

	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`

	AdditionalFields map[string]interface{}
}

// ToDeviceCodeResult converts the DeviceCodeResponse to a DeviceCodeResult
func (dcr DeviceCodeResponse) ToDeviceCodeResult(clientID string, scopes []string) msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.CreateDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// Client represents the REST calls to get tokens from token generator backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm          urlFormCaller
	TokenRespFunc createTokenResp
}

// GetAccessTokenFromUsernamePassword uses a username and password to get an access token.
func (c Client) GetAccessTokenFromUsernamePassword(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, msalbase.PasswordGrant)
	qv.Set(username, authParameters.Username)
	qv.Set(password, authParameters.Password)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

// GetAccessTokenFromAuthCode uses an authorization code to retrieve an access token.
func (c Client) GetAccessTokenFromAuthCode(ctx context.Context, authParameters msalbase.AuthParametersInternal, authCode string, codeVerifier string, params url.Values) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, msalbase.AuthCodeGrant)
	qv.Set("code", authCode)
	qv.Set("code_verifier", codeVerifier)
	qv.Set("redirect_uri", authParameters.Redirecturi)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	// TODO(msal): Hey, if we don't need for these params to override the values above, we
	// should just do params.Set() for all values above and repeat that for each method in
	// this client.  Can someone answer that questions?
	for k, v := range params {
		qv[k] = v
	}
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

// GetAccessTokenFromRefreshToken uses a refresh token (for refreshing credentials) to get a new access token.
func (c Client) GetAccessTokenFromRefreshToken(ctx context.Context, authParameters msalbase.AuthParametersInternal, refreshToken string, params url.Values) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, msalbase.RefreshTokenGrant)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("refresh_token", refreshToken)
	for k, v := range params {
		qv[k] = v
	}
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

// GetAccessTokenWithClientSecret uses a client's secret (aka password) to get a new token.
func (c Client) GetAccessTokenWithClientSecret(ctx context.Context, authParameters msalbase.AuthParametersInternal, clientSecret string) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, msalbase.ClientCredentialGrant)
	qv.Set("client_secret", clientSecret)
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetAccessTokenWithAssertion(ctx context.Context, authParameters msalbase.AuthParametersInternal, assertion string) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, msalbase.ClientCredentialGrant)
	qv.Set("client_assertion_type", msalbase.ClientAssertionGrant)
	qv.Set("client_assertion", assertion)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.DeviceCodeResult, error) {
	qv := url.Values{}
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	endpoint := strings.Replace(authParameters.Endpoints.TokenEndpoint, "token", "devicecode", -1)

	resp := DeviceCodeResponse{}
	err := c.Comm.URLFormCall(ctx, endpoint, qv, &resp)
	if err != nil {
		return msalbase.DeviceCodeResult{}, err
	}

	return resp.ToDeviceCodeResult(authParameters.ClientID, authParameters.Scopes), nil
}

func (c Client) GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal, deviceCodeResult msalbase.DeviceCodeResult) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, msalbase.DeviceCodeGrant)
	qv.Set(deviceCode, deviceCodeResult.GetDeviceCode())
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetAccessTokenFromSamlGrant(ctx context.Context, authParameters msalbase.AuthParametersInternal, samlGrant wstrust.SamlTokenInfo) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(username, authParameters.Username)
	qv.Set(password, authParameters.Password)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("assertion", base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString([]byte(samlGrant.Assertion)))
	addScopeQueryParam(qv, authParameters)

	switch samlGrant.AssertionType {
	case msalbase.SAMLV1Grant:
		qv.Set(grantType, msalbase.SAMLV1Grant)
	case msalbase.SAMLV2Grant:
		qv.Set(grantType, msalbase.SAMLV2Grant)
	default:
		return msalbase.TokenResponse{}, fmt.Errorf("GetAccessTokenFromSamlGrant returned unknown SAML assertion type: %q", samlGrant.AssertionType)
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) doTokenResp(ctx context.Context, authParameters msalbase.AuthParametersInternal, qv url.Values) (msalbase.TokenResponse, error) {
	// TODO(jdoak): This should really go straight to TokenResponse and not TokenResponseJSONPayload.
	resp := msalbase.TokenResponseJSONPayload{}
	err := c.Comm.URLFormCall(ctx, authParameters.Endpoints.TokenEndpoint, qv, &resp)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	// TODO(jdoak): As above, this shouldn't be needed.
	return c.TokenRespFunc(authParameters, resp)
}

// openid required to get an id token
// offline_access required to get a refresh token
// profile required to get the client_info field back
var defaultScopes = []string{"openid", "offline_access", "profile"}

func addScopeQueryParam(queryParams url.Values, authParameters msalbase.AuthParametersInternal) {
	scopes := make([]string, len(authParameters.Scopes)+len(defaultScopes))
	copy(scopes, authParameters.Scopes)
	scopes = append(scopes, defaultScopes...)
	queryParams.Set("scope", strings.Join(scopes, " "))
}

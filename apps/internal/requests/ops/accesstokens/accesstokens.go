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

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/internal/grant"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/wstrust"
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

//go:generate stringer -type=AuthCodeRequestType

// AuthCodeRequestType is whether the authorization code flow is for a public or confidential client
// RefreshTokenReqType
// TODO(jdoak): Replace this and anything like this(RefreshTokenReqType...) that has "confidential" or "public" with
// a single type that is called AppType.
type AuthCodeRequestType int

const (
	UnknownAuthCodeType AuthCodeRequestType = iota
	AuthCodePublic
	AuthCodeConfidential
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
	return msalbase.NewDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
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
	qv.Set(grantType, grant.Password)
	qv.Set(username, authParameters.Username)
	qv.Set(password, authParameters.Password)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	AuthParams    msalbase.AuthParametersInternal
	Code          string
	CodeChallenge string
	Credential    *msalbase.Credential
	RequestType   AuthCodeRequestType
}

// NewCodeChallengeRequest returns a request
func NewCodeChallengeRequest(params msalbase.AuthParametersInternal, rt AuthCodeRequestType, cc *msalbase.Credential, code, challenge string) (AuthCodeRequest, error) {
	if rt == UnknownAuthCodeType {
		return AuthCodeRequest{}, fmt.Errorf("bug: NewCodeChallengeRequest() called with AuthCodeRequestType == UnknownAuthCodeType")
	}
	return AuthCodeRequest{
		AuthParams:    params,
		RequestType:   rt,
		Code:          code,
		CodeChallenge: challenge,
		Credential:    cc,
	}, nil
}

// GetAccessTokenFromAuthCode uses an authorization code to retrieve an access token.
func (c Client) GetAccessTokenFromAuthCode(ctx context.Context, req AuthCodeRequest) (msalbase.TokenResponse, error) {
	var qv url.Values

	switch req.RequestType {
	case UnknownAuthCodeType:
		return msalbase.TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with RequestType == UnknownAuthCodeType")
	case AuthCodeConfidential:
		var err error
		qv, err = prepURLVals(req.Credential, req.AuthParams)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
	case AuthCodePublic:
		// Nothing needs to be done, exept to not error.
	default:
		return msalbase.TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with RequestType == %s, which we do not recongnize", req.RequestType)
	}

	qv.Set(grantType, grant.AuthCode)
	qv.Set("code", req.Code)
	qv.Set("code_verifier", req.CodeChallenge)
	qv.Set("redirect_uri", req.AuthParams.Redirecturi)
	qv.Set(clientID, req.AuthParams.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, req.AuthParams)

	return c.doTokenResp(ctx, req.AuthParams, qv)
}

//go:generate stringer -type=RefreshTokenReqType

// RefreshTokenReqType is whether the refresh token flow is for a public or confidential client
// TODO(jdoak): Replace this and anything like this that has "confidential" or "public" with
// a single type that is called AppType.
type RefreshTokenReqType int

//These are the different values for RefreshTokenReqType
const (
	RefreshTokenUnknown RefreshTokenReqType = iota
	RefreshTokenPublic
	RefreshTokenConfidential
)

// GetAccessTokenFromRefreshToken uses a refresh token (for refreshing credentials) to get a new access token.
func (c Client) GetAccessTokenFromRefreshToken(ctx context.Context, rtType RefreshTokenReqType, authParams msalbase.AuthParametersInternal, cc *msalbase.Credential, refreshToken string) (msalbase.TokenResponse, error) {
	var qv url.Values
	if rtType == RefreshTokenConfidential {
		var err error
		qv, err = prepURLVals(cc, authParams)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
	}
	qv.Set(grantType, grant.RefreshToken)
	qv.Set(clientID, authParams.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("refresh_token", refreshToken)
	addScopeQueryParam(qv, authParams)

	return c.doTokenResp(ctx, authParams, qv)
}

// GetAccessTokenWithClientSecret uses a client's secret (aka password) to get a new token.
func (c Client) GetAccessTokenWithClientSecret(ctx context.Context, authParameters msalbase.AuthParametersInternal, clientSecret string) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set("client_secret", clientSecret)
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetAccessTokenWithAssertion(ctx context.Context, authParameters msalbase.AuthParametersInternal, assertion string) (msalbase.TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set("client_assertion_type", grant.ClientAssertion)
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
	qv.Set(grantType, grant.DeviceCode)
	qv.Set(deviceCode, deviceCodeResult.DeviceCode)
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
	case grant.SAMLV1:
		qv.Set(grantType, grant.SAMLV1)
	case grant.SAMLV2:
		qv.Set(grantType, grant.SAMLV2)
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

// prepURLVals returns an url.Values that sets various key/values if we are doing secrets
// or JWT assertions.
func prepURLVals(cc *msalbase.Credential, authParams msalbase.AuthParametersInternal) (url.Values, error) {
	params := url.Values{}
	if cc.Secret != "" {
		params.Set("client_secret", cc.Secret)
		return params, nil
	}

	jwt, err := cc.JWT(authParams)
	if err != nil {
		return nil, err
	}
	params.Set("client_assertion", jwt)
	params.Set("client_assertion_type", grant.ClientAssertion)
	return params, nil
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

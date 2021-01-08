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
	"crypto"

	/* #nosec */
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/internal/grant"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
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

type createTokenResp func(authParameters authority.AuthParams, payload TokenResponseJSONPayload) (TokenResponse, error)

// DeviceCodeResponse represents the HTTP response received from the device code endpoint
type DeviceCodeResponse struct {
	authority.OAuthResponseBase

	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`

	AdditionalFields map[string]interface{}
}

// ToDeviceCodeResult converts the DeviceCodeResponse to a DeviceCodeResult
func (dcr DeviceCodeResponse) ToDeviceCodeResult(clientID string, scopes []string) DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return NewDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// Credential represents the credential used in confidential client flows. This can be either
// a Secret or Cert/Key.
type Credential struct {
	// Secret contains the credential secret if we are doing auth by secret.
	Secret string

	// Cert is the public x509 certificate if we are doing any auth other than secret.
	Cert *x509.Certificate
	// Key is the private key for signing if we are doing any auth other than secret.
	Key crypto.PrivateKey

	// mu protects everything below.
	mu sync.Mutex
	// Assertion is the JWT assertion if we have retrieved it. Public to allow faking in tests.
	// Any use outside msal is not supported by a compatibility promise.
	Assertion string
	// Expires is when the Assertion expires. Public to allow faking in tests.
	// Any use outside msal is not supported by a compatibility promise.
	Expires time.Time
}

// JWT gets the jwt assertion when the credential is not using a secret.
func (c *Credential) JWT(authParams authority.AuthParams) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Expires.Before(time.Now()) && c.Assertion != "" {
		return c.Assertion, nil
	}
	// TODO(msal): The reasoning for this needs to be documented somewhere.
	// I don't have any logical reason that the JWT should expire at any certain time.
	// Why ask for only 5 minutes, why not 10, 20, 30, 1hour...
	expires := time.Now().Add(5 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": authParams.Endpoints.TokenEndpoint,
		"exp": strconv.FormatInt(expires.Unix(), 10),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": strconv.FormatInt(time.Now().Unix(), 10),
		"sub": authParams.ClientID,
	})
	token.Header = map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": base64.StdEncoding.EncodeToString(thumbprint(c.Cert)),
	}

	var err error
	c.Assertion, err = token.SignedString(c.Key)
	if err != nil {
		return "", fmt.Errorf("unable to sign a JWT token using private key: %w", err)
	}

	c.Expires = expires
	return c.Assertion, nil
}

// thumbprint runs the asn1.Der bytes through sha1 for use in the x5t parameter of JWT.
// https://tools.ietf.org/html/rfc7517#section-4.8
func thumbprint(cert *x509.Certificate) []byte {
	/* #nosec */
	a := sha1.Sum(cert.Raw)
	return a[:]
}

// Client represents the REST calls to get tokens from token generator backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm          urlFormCaller
	TokenRespFunc createTokenResp
}

// GetAccessTokenFromUsernamePassword uses a username and password to get an access token.
func (c Client) GetAccessTokenFromUsernamePassword(ctx context.Context, authParameters authority.AuthParams) (TokenResponse, error) {
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
	AuthParams    authority.AuthParams
	Code          string
	CodeChallenge string
	Credential    *Credential
	RequestType   AuthCodeRequestType
}

// NewCodeChallengeRequest returns a request
func NewCodeChallengeRequest(params authority.AuthParams, rt AuthCodeRequestType, cc *Credential, code, challenge string) (AuthCodeRequest, error) {
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
func (c Client) GetAccessTokenFromAuthCode(ctx context.Context, req AuthCodeRequest) (TokenResponse, error) {
	var qv url.Values

	switch req.RequestType {
	case UnknownAuthCodeType:
		return TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with RequestType == UnknownAuthCodeType")
	case AuthCodeConfidential:
		var err error
		if req.Credential == nil {
			return TokenResponse{}, fmt.Errorf("AuthCodeRequest had nil Credential for Confidential app")
		}
		qv, err = prepURLVals(req.Credential, req.AuthParams)
		if err != nil {
			return TokenResponse{}, err
		}
	case AuthCodePublic:
		// Nothing needs to be done, exept to not error.
	default:
		return TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with RequestType == %v, which we do not recongnize", req.RequestType)
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
func (c Client) GetAccessTokenFromRefreshToken(ctx context.Context, rtType RefreshTokenReqType, authParams authority.AuthParams, cc *Credential, refreshToken string) (TokenResponse, error) {
	qv := url.Values{}
	if rtType == RefreshTokenConfidential {
		var err error
		qv, err = prepURLVals(cc, authParams)
		if err != nil {
			return TokenResponse{}, err
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
func (c Client) GetAccessTokenWithClientSecret(ctx context.Context, authParameters authority.AuthParams, clientSecret string) (TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set("client_secret", clientSecret)
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	token, err := c.doTokenResp(ctx, authParameters, qv)
	if err != nil {
		return token, fmt.Errorf("GetAccessTokenWithClientSecret(): %w", err)
	}
	return token, nil
}

func (c Client) GetAccessTokenWithAssertion(ctx context.Context, authParameters authority.AuthParams, assertion string) (TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set("client_assertion_type", grant.ClientAssertion)
	qv.Set("client_assertion", assertion)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	token, err := c.doTokenResp(ctx, authParameters, qv)
	if err != nil {
		return token, fmt.Errorf("GetAccessTokenWithAssertion(): %w", err)
	}
	return token, nil
}

func (c Client) GetDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams) (DeviceCodeResult, error) {
	qv := url.Values{}
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	endpoint := strings.Replace(authParameters.Endpoints.TokenEndpoint, "token", "devicecode", -1)

	resp := DeviceCodeResponse{}
	err := c.Comm.URLFormCall(ctx, endpoint, qv, &resp)
	if err != nil {
		return DeviceCodeResult{}, err
	}

	return resp.ToDeviceCodeResult(authParameters.ClientID, authParameters.Scopes), nil
}

func (c Client) GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams, deviceCodeResult DeviceCodeResult) (TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, grant.DeviceCode)
	qv.Set(deviceCode, deviceCodeResult.DeviceCode)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetAccessTokenFromSamlGrant(ctx context.Context, authParameters authority.AuthParams, samlGrant wstrust.SamlTokenInfo) (TokenResponse, error) {
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
		return TokenResponse{}, fmt.Errorf("GetAccessTokenFromSamlGrant returned unknown SAML assertion type: %q", samlGrant.AssertionType)
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) doTokenResp(ctx context.Context, authParameters authority.AuthParams, qv url.Values) (TokenResponse, error) {
	// TODO(jdoak): This should really go straight to TokenResponse and not TokenResponseJSONPayload.
	resp := TokenResponseJSONPayload{}
	err := c.Comm.URLFormCall(ctx, authParameters.Endpoints.TokenEndpoint, qv, &resp)
	if err != nil {
		return TokenResponse{}, err
	}
	// TODO(jdoak): As above, this shouldn't be needed.
	return c.TokenRespFunc(authParameters, resp)
}

// prepURLVals returns an url.Values that sets various key/values if we are doing secrets
// or JWT assertions.
func prepURLVals(cc *Credential, authParams authority.AuthParams) (url.Values, error) {
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
var detectDefaultScopes = map[string]bool{
	"openid":         true,
	"offline_access": true,
	"profile":        true,
}

var defaultScopes = []string{"openid", "offline_access", "profile"}

func addScopeQueryParam(queryParams url.Values, authParameters authority.AuthParams) {
	scopes := make([]string, 0, len(authParameters.Scopes)+len(defaultScopes))
	for _, scope := range authParameters.Scopes {
		s := strings.TrimSpace(scope)
		if s == "" {
			continue
		}
		if detectDefaultScopes[scope] {
			continue
		}
		scopes = append(scopes, scope)
	}
	scopes = append(scopes, defaultScopes...)

	queryParams.Set("scope", strings.Join(scopes, " "))
}

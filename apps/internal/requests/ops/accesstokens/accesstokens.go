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
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/internal/grant"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/wstrust"
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
func (dcr DeviceCodeResponse) ToDeviceCodeResult(clientID string, scopes []string) msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.NewDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// Credential represents the credential used in confidential client flows. This can be either
// a Secret or Cert/Key.
type Credential struct {
	Secret string

	Cert *x509.Certificate
	Key  crypto.PrivateKey

	mu        sync.Mutex
	assertion string
	expires   time.Time
}

// JWT gets the jwt assertion when the credential is not using a secret.
func (c *Credential) JWT(authParams authority.AuthParams) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.expires.Before(time.Now()) && c.assertion != "" {
		return c.assertion, nil
	}
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
	c.assertion, err = token.SignedString(c.Key)
	if err != nil {
		return "", err
	}

	c.expires = expires
	return c.assertion, err
}

// thumbprint runs the asn1.Der bytes through sha1 for use in the x5t parameter of JWT.
// https://tools.ietf.org/html/rfc7517#section-4.8
func thumbprint(cert *x509.Certificate) []byte {
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
		qv, err = prepURLVals(req.Credential, req.AuthParams)
		if err != nil {
			return TokenResponse{}, err
		}
	case AuthCodePublic:
		// Nothing needs to be done, exept to not error.
	default:
		return TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with RequestType == %s, which we do not recongnize", req.RequestType)
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
	var qv url.Values
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

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetAccessTokenWithAssertion(ctx context.Context, authParameters authority.AuthParams, assertion string) (TokenResponse, error) {
	qv := url.Values{}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set("client_assertion_type", grant.ClientAssertion)
	qv.Set("client_assertion", assertion)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) GetDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams) (msalbase.DeviceCodeResult, error) {
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

func (c Client) GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams, deviceCodeResult msalbase.DeviceCodeResult) (TokenResponse, error) {
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
var defaultScopes = []string{"openid", "offline_access", "profile"}

func addScopeQueryParam(queryParams url.Values, authParameters authority.AuthParams) {
	scopes := make([]string, len(authParameters.Scopes)+len(defaultScopes))
	copy(scopes, authParameters.Scopes)
	scopes = append(scopes, defaultScopes...)
	queryParams.Set("scope", strings.Join(scopes, " "))
}

type TokenResponseJSONPayload struct {
	authority.OAuthResponseBase

	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	Foci         string `json:"foci"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	// TODO(msal): If this is always going to be a JWT base64 encoded, we should consider
	// making this a json.RawMessage. Then we can do our decodes in []byte and pass it
	// to our json decoder directly instead of all the extra copies from using string.
	// This means changing decodeJWT().
	ClientInfo string `json:"client_info"`

	AdditionalFields map[string]interface{}
}

// ClientInfoJSONPayload is used to create a Home Account ID for an account.
type ClientInfoJSONPayload struct {
	UID  string `json:"uid"`
	Utid string `json:"utid"`

	AdditionalFields map[string]interface{}
}

// IDToken consists of all the information used to validate a user.
// https://docs.microsoft.com/azure/active-directory/develop/id-tokens .
type IDToken struct {
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Name              string `json:"name,omitempty"`
	Oid               string `json:"oid,omitempty"`
	TenantID          string `json:"tid,omitempty"`
	Subject           string `json:"sub,omitempty"`
	UPN               string `json:"upn,omitempty"`
	Email             string `json:"email,omitempty"`
	AlternativeID     string `json:"alternative_id,omitempty"`
	Issuer            string `json:"iss,omitempty"`
	Audience          string `json:"aud,omitempty"`
	ExpirationTime    int64  `json:"exp,omitempty"`
	IssuedAt          int64  `json:"iat,omitempty"`
	NotBefore         int64  `json:"nbf,omitempty"`
	RawToken          string

	AdditionalFields map[string]interface{}
}

// NewIDToken creates an ID token instance from a JWT.
func NewIDToken(jwt string) (IDToken, error) {
	jwtArr := strings.Split(jwt, ".")
	if len(jwtArr) < 2 {
		return IDToken{}, errors.New("id token returned from server is invalid")
	}
	jwtPart := jwtArr[1]
	jwtDecoded, err := decodeJWT(jwtPart)
	if err != nil {
		return IDToken{}, err
	}
	idToken := IDToken{}
	err = json.Unmarshal(jwtDecoded, &idToken)
	if err != nil {
		return IDToken{}, err
	}
	idToken.RawToken = jwt
	return idToken, nil
}

// IsZero indicates if the IDToken is the zero value.
func (i IDToken) IsZero() bool {
	v := reflect.ValueOf(i)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			return false
		}
	}
	return true
}

// GetLocalAccountID extracts an account's local account ID from an ID token.
func (i IDToken) GetLocalAccountID() string {
	if i.Oid != "" {
		return i.Oid
	}
	return i.Subject
}

// TokenResponse is the information that is returned from a token endpoint during a token acquisition flow.
// TODO(jdoak): There is this tokenResponsePayload and TokenResponse.  This just needs a custom unmarshaller
// and we can get rid of having two.
type TokenResponse struct {
	authority.OAuthResponseBase

	AccessToken    string
	RefreshToken   string
	IDToken        IDToken
	FamilyID       string
	GrantedScopes  []string
	DeclinedScopes []string
	ExpiresOn      time.Time
	ExtExpiresOn   time.Time
	RawClientInfo  string
	ClientInfo     ClientInfoJSONPayload

	AdditionalFields map[string]interface{}
}

// HasAccessToken checks if the TokenResponse has an access token.
func (tr TokenResponse) HasAccessToken() bool {
	return len(tr.AccessToken) > 0
}

// HasRefreshToken checks if the TokenResponse has an refresh token.
func (tr TokenResponse) HasRefreshToken() bool {
	return len(tr.RefreshToken) > 0
}

// GetHomeAccountIDFromClientInfo creates the home account ID for an account from the client info parameter.
func (tr TokenResponse) GetHomeAccountIDFromClientInfo() string {
	if tr.ClientInfo.UID == "" || tr.ClientInfo.Utid == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", tr.ClientInfo.UID, tr.ClientInfo.Utid)
}

// NewTokenResponse creates a TokenResponse instance from the response from the token endpoint.
func NewTokenResponse(authParameters authority.AuthParams, payload TokenResponseJSONPayload) (TokenResponse, error) {
	if payload.Error != "" {
		return TokenResponse{}, fmt.Errorf("%s: %s", payload.Error, payload.ErrorDescription)
	}

	if payload.AccessToken == "" {
		// Access token is required in a token response
		return TokenResponse{}, errors.New("response is missing access_token")
	}

	rawClientInfo := payload.ClientInfo
	clientInfo := ClientInfoJSONPayload{}
	// Client info may be empty in some flows, e.g. certificate exchange.
	if len(rawClientInfo) > 0 {
		rawClientInfoDecoded, err := decodeJWT(rawClientInfo)
		if err != nil {
			return TokenResponse{}, err
		}

		err = json.Unmarshal(rawClientInfoDecoded, &clientInfo)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	expiresOn := time.Now().Add(time.Second * time.Duration(payload.ExpiresIn))
	extExpiresOn := time.Now().Add(time.Second * time.Duration(payload.ExtExpiresIn))

	var (
		grantedScopes  []string
		declinedScopes []string
	)

	if len(payload.Scope) == 0 {
		// Per OAuth spec, if no scopes are returned, the response should be treated as if all scopes were granted
		// This behavior can be observed in client assertion flows, but can happen at any time, this check ensures we treat
		// those special responses properly
		// Link to spec: https://tools.ietf.org/html/rfc6749#section-3.3
		grantedScopes = authParameters.Scopes
	} else {
		grantedScopes = strings.Split(strings.ToLower(payload.Scope), " ")
		declinedScopes = findDeclinedScopes(authParameters.Scopes, grantedScopes)
	}

	// ID tokens aren't always returned, which is not a reportable error condition.
	// So we ignore it.
	idToken, _ := NewIDToken(payload.IDToken)

	tokenResponse := TokenResponse{
		OAuthResponseBase: payload.OAuthResponseBase,
		AccessToken:       payload.AccessToken,
		RefreshToken:      payload.RefreshToken,
		IDToken:           idToken,
		FamilyID:          payload.Foci,
		ExpiresOn:         expiresOn,
		ExtExpiresOn:      extExpiresOn,
		GrantedScopes:     grantedScopes,
		DeclinedScopes:    declinedScopes,
		RawClientInfo:     rawClientInfo,
		ClientInfo:        clientInfo,
	}
	return tokenResponse, nil
}

func findDeclinedScopes(requestedScopes []string, grantedScopes []string) []string {
	declined := []string{}
	grantedMap := map[string]bool{}
	for _, s := range grantedScopes {
		grantedMap[s] = true
	}
	// Comparing the requested scopes with the granted scopes to see if there are any scopes that have been declined.
	for _, r := range requestedScopes {
		if !grantedMap[r] {
			declined = append(declined, r)
		}
	}
	return declined
}

// decodeJWT decodes a JWT and converts it to a byte array representing a JSON object
// Adapted from MSAL Python and https://stackoverflow.com/a/31971780 .
func decodeJWT(data string) ([]byte, error) {
	if i := len(data) % 4; i != 0 {
		data += strings.Repeat("=", 4-i)
	}
	return base64.StdEncoding.DecodeString(data)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/resolvers"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/storage"
)

type resolveEndpointer interface {
	ResolveEndpoints(ctx context.Context, authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (msalbase.AuthorityEndpoints, error)
}

//go:generate stringer -type=AuthCodeRequestType

// AuthCodeRequestType is whether the authorization code flow is for a public or confidential client
type AuthCodeRequestType int

const (
	UnknownAuthCodeType AuthCodeRequestType = iota
	AuthCodePublic
	AuthCodeConfidential
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	authParameters msalbase.AuthParametersInternal
	Code           string
	CodeChallenge  string
	Credential     *msalbase.Credential
	RequestType    AuthCodeRequestType
}

// NewCodeChallengeRequest returns a request
func NewCodeChallengeRequest(params msalbase.AuthParametersInternal, rt AuthCodeRequestType, cc *msalbase.Credential, code, challenge string) (AuthCodeRequest, error) {
	if rt == UnknownAuthCodeType {
		return AuthCodeRequest{}, fmt.Errorf("bug: NewCodeChallengeRequest() called with AuthCodeRequestType == UnknownAuthCodeType")
	}
	return AuthCodeRequest{
		authParameters: params,
		RequestType:    rt,
		Code:           code,
		CodeChallenge:  challenge,
		Credential:     cc,
	}, nil
}

//go:generate stringer -type=RefreshTokenReqType

// RefreshTokenReqType is whether the refresh token flow is for a public or confidential client
type RefreshTokenReqType int

//These are the different values for RefreshTokenReqType
const (
	RefreshTokenUnknown RefreshTokenReqType = iota
	RefreshTokenPublic
	RefreshTokenConfidential
)

// Token provides tokens for various types of token requests.
type Token struct {
	resolver resolveEndpointer
	rest     *ops.REST

	//manager manager // *storage.Manager or fakeManager in tests
}

// NewToken is the constructor for Token.
func NewToken(resolver *resolvers.AuthorityEndpoint) *Token {
	return &Token{resolver: resolver}
}

// AuthCode requturns a token based on an authorization code.
func (t *Token) AuthCode(ctx context.Context, req AuthCodeRequest) (msalbase.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &req.authParameters, ""); err != nil {
		return msalbase.TokenResponse{}, err
	}

	params := url.Values{}
	switch req.RequestType {
	case UnknownAuthCodeType:
		return msalbase.TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with RequestType == UnknownAuthCodeType")
	case AuthCodeConfidential:
		var err error
		params, err = t.prepURLVals(req.Credential, req.authParameters)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
	case AuthCodePublic:
		tResp, err := t.rest.AccessTokens().GetAccessTokenFromAuthCode(ctx, req.authParameters, req.Code, req.CodeChallenge, params)
		if err != nil {
			return msalbase.TokenResponse{}, fmt.Errorf("could not retrieve token from auth code: %w", err)
		}
		return tResp, nil
	}

	return msalbase.TokenResponse{}, fmt.Errorf("Token.AuthCode() received request with unsupported RequestType == %v", req.RequestType)
}

// Credential acquires a token from the authority using a client credentials grant.
func (t *Token) Credential(ctx context.Context, authParams msalbase.AuthParametersInternal, cred *msalbase.Credential) (msalbase.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return msalbase.TokenResponse{}, err
	}

	if cred.Secret != "" {
		return t.rest.AccessTokens().GetAccessTokenWithClientSecret(ctx, authParams, cred.Secret)
	}

	jwt, err := cred.JWT(authParams)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	return t.rest.AccessTokens().GetAccessTokenWithAssertion(ctx, authParams, jwt)
}

func (t *Token) Refresh(ctx context.Context, authParams msalbase.AuthParametersInternal, cc *msalbase.Credential, refreshToken storage.RefreshToken, reqType RefreshTokenReqType) (msalbase.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return msalbase.TokenResponse{}, err
	}

	params := url.Values{}
	if reqType == RefreshTokenConfidential {
		var err error
		params, err = t.prepURLVals(cc, authParams)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
	}
	return t.rest.AccessTokens().GetAccessTokenFromRefreshToken(ctx, authParams, refreshToken.Secret, params)
}

// UsernamePassword rertieves a token where a username and password is used. However, if this is
// a user realm of "Federated", this uses SAML tokens. If "Managed", uses normal username/password.
func (t *Token) UsernamePassword(ctx context.Context, authParams msalbase.AuthParametersInternal) (msalbase.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return msalbase.TokenResponse{}, err
	}

	userRealm, err := t.rest.Authority().GetUserRealm(ctx, authParams)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}

	switch accountType := userRealm.GetAccountType(); accountType {
	case msalbase.Federated:
		mexDoc, err := t.rest.WSTrust().GetMex(ctx, userRealm.FederationMetadataURL)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}

		saml, err := t.rest.WSTrust().GetSAMLTokenInfo(ctx, authParams, userRealm.CloudAudienceURN, mexDoc.UsernamePasswordEndpoint)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		return t.rest.AccessTokens().GetAccessTokenFromSamlGrant(ctx, authParams, saml)
	case msalbase.Managed:
		return t.rest.AccessTokens().GetAccessTokenFromUsernamePassword(ctx, authParams)
	}
	return msalbase.TokenResponse{}, errors.New("unknown account type")
}

// DeviceCode is the result of a call to Token.DeviceCode().
type DeviceCode struct {
	// Result is the device code result from the first call in the device code flow. This allows
	// the caller to retrieve the displayed code that is used to authorize on the second device.
	Result     msalbase.DeviceCodeResult
	authParams msalbase.AuthParametersInternal

	// Note: Normally you don't embed a Context, but this is safe as it is only used for a single
	// call and it is scoped to that calls lifetime.
	ctx    context.Context
	cancel context.CancelFunc
	rest   *ops.REST
}

// Token returns a token AFTER the user uses the device code on the second device. This will block
// until either: (1) the code is input by the user and the service releases a token, (2) the token
// expires, (3) the Context passed to .DeviceCode() is cancelled or expires, (4) some other service
// error occurs.
func (d DeviceCode) Token() (msalbase.TokenResponse, error) {
	defer d.cancel()

	var interval = 50 * time.Millisecond
	for {
		time.Sleep(interval)
		interval += interval * 2
		if interval > 5*time.Second {
			interval = 5 * time.Second
		}

		token, err := d.rest.AccessTokens().GetAccessTokenFromDeviceCodeResult(d.ctx, d.authParams, d.Result)
		if err != nil && isWaitDeviceCodeErr(err) {
			continue
		}
		return token, err // This handles if it was a non-wait error or success
	}
}

var waitRE = regexp.MustCompile("(authorization_pending|slow_down)")

// TODO(msal): This is freaking terrible. The original just looked for the exact word in the error output.
// I doubt this worked. I don't know if the service really does this, but it should send back a structured
// error response. Anyways, I updated this to search the entire return error message, which will be the body
// of the return.
func isWaitDeviceCodeErr(err error) bool {
	return waitRE.MatchString(err.Error())
}

// DeviceCode returns a DeviceCode object that can be used to get the code that must be entered on the second
// device and optionally the token once the code has been entered on the second device.
func (t *Token) DeviceCode(ctx context.Context, authParams msalbase.AuthParametersInternal) (DeviceCode, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return DeviceCode{}, err
	}

	dcr, err := t.rest.AccessTokens().GetDeviceCodeResult(ctx, authParams)
	if err != nil {
		return DeviceCode{}, err
	}

	var cancel context.CancelFunc
	dcr.GetExpiresOn().Sub(time.Now().UTC())
	if deadline, ok := ctx.Deadline(); !ok || dcr.GetExpiresOn().Before(deadline) {
		ctx, cancel = context.WithDeadline(ctx, dcr.GetExpiresOn())
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	return DeviceCode{Result: dcr, authParams: authParams, ctx: ctx, cancel: cancel, rest: t.rest}, nil
}

func (t *Token) resolveEndpoint(ctx context.Context, authParams *msalbase.AuthParametersInternal, userPrincipalName string) error {
	endpoints, err := t.resolver.ResolveEndpoints(ctx, authParams.AuthorityInfo, userPrincipalName)
	if err != nil {
		return err
	}
	authParams.Endpoints = endpoints
	return nil
}

func (t *Token) prepURLVals(cc *msalbase.Credential, authParams msalbase.AuthParametersInternal) (url.Values, error) {
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
	params.Set("client_assertion_type", msalbase.ClientAssertionGrant)
	return params, nil
}

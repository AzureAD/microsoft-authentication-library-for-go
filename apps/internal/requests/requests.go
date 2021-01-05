// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/wstrust"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/wstrust/defs"
)

type resolveEndpointer interface {
	ResolveEndpoints(ctx context.Context, authorityInfo authority.Info, userPrincipalName string) (authority.Endpoints, error)
}

type accessTokens interface {
	GetAccessTokenFromUsernamePassword(ctx context.Context, authParameters authority.AuthParams) (accesstokens.TokenResponse, error)
	GetAccessTokenFromAuthCode(ctx context.Context, req accesstokens.AuthCodeRequest) (accesstokens.TokenResponse, error)
	GetAccessTokenFromRefreshToken(ctx context.Context, rtType accesstokens.RefreshTokenReqType, authParams authority.AuthParams, cc *accesstokens.Credential, refreshToken string) (accesstokens.TokenResponse, error)
	GetAccessTokenWithClientSecret(ctx context.Context, authParameters authority.AuthParams, clientSecret string) (accesstokens.TokenResponse, error)
	GetAccessTokenWithAssertion(ctx context.Context, authParameters authority.AuthParams, assertion string) (accesstokens.TokenResponse, error)
	GetDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams) (accesstokens.DeviceCodeResult, error)
	GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams, deviceCodeResult accesstokens.DeviceCodeResult) (accesstokens.TokenResponse, error)
	GetAccessTokenFromSamlGrant(ctx context.Context, authParameters authority.AuthParams, samlGrant wstrust.SamlTokenInfo) (accesstokens.TokenResponse, error)
}

type fetchAuthority interface {
	GetUserRealm(context.Context, authority.AuthParams) (authority.UserRealm, error)
	GetAadinstanceDiscoveryResponse(context.Context, authority.Info) (authority.InstanceDiscoveryResponse, error)
}

type fetchWSTrust interface {
	GetMex(ctx context.Context, federationMetadataURL string) (defs.MexDocument, error)
	GetSAMLTokenInfo(ctx context.Context, authParameters authority.AuthParams, cloudAudienceURN string, endpoint defs.Endpoint) (wstrust.SamlTokenInfo, error)
}

// Token provides tokens for various types of token requests.
type Token struct {
	resolver     resolveEndpointer
	accessTokens accessTokens
	authority    fetchAuthority
	wsTrust      fetchWSTrust
}

// NewToken is the constructor for Token.
func NewToken() *Token {
	r := ops.New()
	return &Token{
		resolver:     newAuthorityEndpoint(r),
		accessTokens: r.AccessTokens(),
		authority:    r.Authority(),
		wsTrust:      r.WSTrust(),
	}
}

// ResolveEndpoints gets the authorization and token endpoints and creates an AuthorityEndpoints instance.
func (t *Token) ResolveEndpoints(ctx context.Context, authorityInfo authority.Info, userPrincipalName string) (authority.Endpoints, error) {
	return t.resolver.ResolveEndpoints(ctx, authorityInfo, userPrincipalName)
}

func (t *Token) GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryResponse, error) {
	return t.authority.GetAadinstanceDiscoveryResponse(ctx, authorityInfo)
}

// AuthCode returns a token based on an authorization code.
func (t *Token) AuthCode(ctx context.Context, req accesstokens.AuthCodeRequest) (accesstokens.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &req.AuthParams, ""); err != nil {
		return accesstokens.TokenResponse{}, err
	}

	tResp, err := t.accessTokens.GetAccessTokenFromAuthCode(ctx, req)
	if err != nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("could not retrieve token from auth code: %w", err)
	}
	return tResp, nil
}

// Credential acquires a token from the authority using a client credentials grant.
func (t *Token) Credential(ctx context.Context, authParams authority.AuthParams, cred *accesstokens.Credential) (accesstokens.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return accesstokens.TokenResponse{}, err
	}

	if cred.Secret != "" {
		return t.accessTokens.GetAccessTokenWithClientSecret(ctx, authParams, cred.Secret)
	}

	jwt, err := cred.JWT(authParams)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	return t.accessTokens.GetAccessTokenWithAssertion(ctx, authParams, jwt)
}

func (t *Token) Refresh(ctx context.Context, reqType accesstokens.RefreshTokenReqType, authParams authority.AuthParams, cc *accesstokens.Credential, refreshToken accesstokens.RefreshToken) (accesstokens.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return accesstokens.TokenResponse{}, err
	}

	return t.accessTokens.GetAccessTokenFromRefreshToken(ctx, reqType, authParams, cc, refreshToken.Secret)
}

// UsernamePassword retrieves a token where a username and password is used. However, if this is
// a user realm of "Federated", this uses SAML tokens. If "Managed", uses normal username/password.
func (t *Token) UsernamePassword(ctx context.Context, authParams authority.AuthParams) (accesstokens.TokenResponse, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return accesstokens.TokenResponse{}, err
	}

	userRealm, err := t.authority.GetUserRealm(ctx, authParams)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}

	switch userRealm.AccountType {
	case authority.Federated:
		mexDoc, err := t.wsTrust.GetMex(ctx, userRealm.FederationMetadataURL)
		if err != nil {
			return accesstokens.TokenResponse{}, err
		}

		saml, err := t.wsTrust.GetSAMLTokenInfo(ctx, authParams, userRealm.CloudAudienceURN, mexDoc.UsernamePasswordEndpoint)
		if err != nil {
			return accesstokens.TokenResponse{}, err
		}
		return t.accessTokens.GetAccessTokenFromSamlGrant(ctx, authParams, saml)
	case authority.Managed:
		return t.accessTokens.GetAccessTokenFromUsernamePassword(ctx, authParams)
	}
	return accesstokens.TokenResponse{}, errors.New("unknown account type")
}

// DeviceCode is the result of a call to Token.DeviceCode().
type DeviceCode struct {
	// Result is the device code result from the first call in the device code flow. This allows
	// the caller to retrieve the displayed code that is used to authorize on the second device.
	Result     accesstokens.DeviceCodeResult
	authParams authority.AuthParams

	// Note: Normally you don't embed a Context, but this is safe as it is only used for a single
	// call and it is scoped to that calls lifetime.
	ctx          context.Context
	cancel       context.CancelFunc
	accessTokens accessTokens
}

// Token returns a token AFTER the user uses the device code on the second device. This will block
// until either: (1) the code is input by the user and the service releases a token, (2) the token
// expires, (3) the Context passed to .DeviceCode() is cancelled or expires, (4) some other service
// error occurs.
func (d DeviceCode) Token() (accesstokens.TokenResponse, error) {
	if d.accessTokens == nil {
		return accesstokens.TokenResponse{}, fmt.Errorf("DeviceCode was either created outside its package or the creating method had an error. DeviceCode is not valid")
	}
	defer d.cancel()

	var interval = 50 * time.Millisecond
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		timer.Reset(interval)
		select {
		case <-d.ctx.Done():
			return accesstokens.TokenResponse{}, d.ctx.Err()
		case <-timer.C:
			interval += interval * 2
			if interval > 5*time.Second {
				interval = 5 * time.Second
			}
		}

		token, err := d.accessTokens.GetAccessTokenFromDeviceCodeResult(d.ctx, d.authParams, d.Result)
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
func (t *Token) DeviceCode(ctx context.Context, authParams authority.AuthParams) (DeviceCode, error) {
	if err := t.resolveEndpoint(ctx, &authParams, ""); err != nil {
		return DeviceCode{}, err
	}

	dcr, err := t.accessTokens.GetDeviceCodeResult(ctx, authParams)
	if err != nil {
		return DeviceCode{}, err
	}

	var cancel context.CancelFunc
	dcr.ExpiresOn.Sub(time.Now().UTC())
	if deadline, ok := ctx.Deadline(); !ok || dcr.ExpiresOn.Before(deadline) {
		ctx, cancel = context.WithDeadline(ctx, dcr.ExpiresOn)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}

	return DeviceCode{Result: dcr, authParams: authParams, ctx: ctx, cancel: cancel, accessTokens: t.accessTokens}, nil
}

func (t *Token) resolveEndpoint(ctx context.Context, authParams *authority.AuthParams, userPrincipalName string) error {
	endpoints, err := t.resolver.ResolveEndpoints(ctx, authParams.AuthorityInfo, userPrincipalName)
	if err != nil {
		return fmt.Errorf("unable to resolve an endpoint: %s", err)
	}
	authParams.Endpoints = endpoints
	return nil
}

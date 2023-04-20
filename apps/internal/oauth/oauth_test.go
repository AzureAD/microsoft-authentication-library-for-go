// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package oauth

// NOTE: These tests cover that we handle errors from other lower level modules.
// We don't actually care about a TokenResponse{}, that is gathered from a remote system
// and they are tested via intergration tests (data retrieved from one system and passed from
// to another). We care about execution behavior (service X says there is an error and we handle it,
// we require .X is set and input doesn't have it, ...)

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/exported"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/fake"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

var testScopes = []string{"scope"}

func TestAuthCode(t *testing.T) {
	tests := []struct {
		desc string
		re   fake.ResolveEndpoints
		at   *fake.AccessTokens
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fake.ResolveEndpoints{Err: true},
			at:   &fake.AccessTokens{},
			err:  true,
		},
		{
			desc: "Error: REST access token error",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{Err: true},
			err:  true,
		},
		{
			desc: "Success",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.AccessTokens = test.at
		token.Resolver = test.re

		_, err := token.AuthCode(context.Background(), accesstokens.AuthCodeRequest{AuthParams: authority.AuthParams{Scopes: testScopes}})
		switch {
		case err == nil && test.err:
			t.Errorf("TestAuthCode(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestAuthCode(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestCredential(t *testing.T) {
	callback := func(context.Context, exported.AssertionRequestOptions) (string, error) {
		return "assertion", nil
	}
	tests := []struct {
		desc       string
		re         fake.ResolveEndpoints
		at         *fake.AccessTokens
		authParams authority.AuthParams
		cred       *accesstokens.Credential
		err        bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fake.ResolveEndpoints{Err: true},
			at:   &fake.AccessTokens{},
			cred: &accesstokens.Credential{
				AssertionCallback: callback,
			},
			err: true,
		},
		{
			desc: "Error: REST access token error on secret",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{Err: true},
			cred: &accesstokens.Credential{
				AssertionCallback: callback,
			},
			err: true,
		},
		{
			desc: "Error: could not generate JWT from cred assertion",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{Err: true},
			cred: &accesstokens.Credential{
				AssertionCallback: callback,
				Cert:              &x509.Certificate{},
				// Key is nil and causes token.SignedString(c.Key) to fail in Credential.JWT()
			},
			err: true,
		},
		{
			desc: "Error: REST access token error on assertion",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{Err: true},
			cred: &accesstokens.Credential{
				AssertionCallback: callback,
			},
			err: true,
		},
		{
			desc: "Success: secret cred",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{},
			cred: &accesstokens.Credential{
				Secret: "secret",
			},
		},
		{
			desc: "Success: assertion cred",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{},
			cred: &accesstokens.Credential{
				AssertionCallback: callback,
			},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.AccessTokens = test.at
		token.Resolver = test.re

		_, err := token.Credential(context.Background(), test.authParams, test.cred)
		switch {
		case err == nil && test.err:
			t.Errorf("TestCredential(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestCredential(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestRefresh(t *testing.T) {
	tests := []struct {
		desc string
		re   fake.ResolveEndpoints
		at   *fake.AccessTokens
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fake.ResolveEndpoints{Err: true},
			at:   &fake.AccessTokens{},
			err:  true,
		},
		{
			desc: "Error: REST access token error",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{Err: true},
			err:  true,
		},
		{
			desc: "Success",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.AccessTokens = test.at
		token.Resolver = test.re

		_, err := token.Refresh(
			context.Background(),
			accesstokens.ATPublic,
			authority.AuthParams{Scopes: testScopes},
			&accesstokens.Credential{},
			accesstokens.RefreshToken{},
		)
		switch {
		case err == nil && test.err:
			t.Errorf("TestRefresh(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestRefresh(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestUsernamePassword(t *testing.T) {
	tests := []struct {
		desc string
		re   fake.ResolveEndpoints
		at   *fake.AccessTokens
		au   fake.Authority
		ws   fake.WSTrust
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fake.ResolveEndpoints{Err: true},
			at:   &fake.AccessTokens{},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Managed}},
			err:  true,
		},
		{
			desc: "Error: authority.Federated and Mex() error",
			re:   fake.ResolveEndpoints{Err: false},
			at:   &fake.AccessTokens{},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Federated}},
			ws:   fake.WSTrust{GetMexErr: true},
			err:  true,
		},
		{
			desc: "Error: authority.Federated and SAMLTokenInfo() error",
			re:   fake.ResolveEndpoints{Err: false},
			at:   &fake.AccessTokens{},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Federated}},
			ws:   fake.WSTrust{GetSAMLTokenInfoErr: true},
			err:  true,
		},
		{
			desc: "Error: authority.Federated and GetAccessTokenFromSamlGrant() error",
			re:   fake.ResolveEndpoints{Err: false},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Federated}},
			at:   &fake.AccessTokens{Err: true},
			err:  true,
		},
		{
			desc: "Error: authority.Managed and REST access token error",
			re:   fake.ResolveEndpoints{Err: false},
			at:   &fake.AccessTokens{Err: true},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Managed}},
			err:  true,
		},
		{
			desc: "Success: authority.Managed",
			re:   fake.ResolveEndpoints{Err: false},
			at:   &fake.AccessTokens{},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Managed}},
		},
		{
			desc: "Success: authority.Federated",
			re:   fake.ResolveEndpoints{Err: false},
			at:   &fake.AccessTokens{},
			au:   fake.Authority{Realm: authority.UserRealm{AccountType: authority.Federated}},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.AccessTokens = test.at
		token.Authority = test.au
		token.Resolver = test.re
		token.WSTrust = test.ws

		_, err := token.UsernamePassword(context.Background(), authority.AuthParams{Scopes: testScopes})
		switch {
		case err == nil && test.err:
			t.Errorf("TestUsernamePassword(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestUsernamePassword(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestDeviceCode(t *testing.T) {
	tests := []struct {
		desc string
		dc   DeviceCode
		err  bool
	}{
		{
			desc: "Error: .accessTokens == nil",
			dc:   DeviceCode{},
			err:  true,
		},
		{
			desc: "Error: FromDeviceCodeResult() returned a !isWaitDeviceCodeErr",
			dc: DeviceCode{
				accessTokens: &fake.AccessTokens{
					Result: []error{
						errors.CallErr{
							Resp: &http.Response{
								StatusCode: 400,
								Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "authorization_pending"}`))),
							},
						},
						errors.CallErr{
							Resp: &http.Response{
								StatusCode: 400,
								Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "slow_down"}`))),
							},
						},
						errors.CallErr{
							Resp: &http.Response{
								StatusCode: 400,
								Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "bad_error"}`))),
							},
						},
						nil,
					},
				},
			},
			err: true,
		},
		{
			desc: "Success",
			dc: DeviceCode{
				Result: accesstokens.DeviceCodeResult{
					ExpiresOn: time.Now().Add(5 * time.Minute),
				},
				accessTokens: &fake.AccessTokens{
					Result: []error{
						errors.CallErr{
							Resp: &http.Response{
								StatusCode: 400,
								Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "authorization_pending"}`))),
							},
						},
						errors.CallErr{
							Resp: &http.Response{
								StatusCode: 400,
								Body:       io.NopCloser(bytes.NewReader([]byte(`{"error": "slow_down"}`))),
							},
						},
						nil,
					},
				},
			},
		},
	}

	for _, test := range tests {
		_, err := test.dc.Token(context.Background())
		switch {
		case err == nil && test.err:
			t.Errorf("TestDeviceCode(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestDeviceCode(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestDeviceCodeToken(t *testing.T) {
	tests := []struct {
		desc string
		re   fake.ResolveEndpoints
		at   *fake.AccessTokens
		err  bool
	}{
		{
			desc: "Error: Unable to resolve endpoints",
			re:   fake.ResolveEndpoints{Err: true},
			at:   &fake.AccessTokens{},
			err:  true,
		},
		{
			desc: "Error: REST access token error",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{Err: true},
			err:  true,
		},
		{
			desc: "Success",
			re:   fake.ResolveEndpoints{},
			at:   &fake.AccessTokens{},
		},
	}

	token := &Client{}
	for _, test := range tests {
		token.AccessTokens = test.at
		token.Resolver = test.re

		dc, err := token.DeviceCode(context.Background(), authority.AuthParams{Scopes: testScopes})
		switch {
		case err == nil && test.err:
			t.Errorf("TestDeviceCodeToken(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestDeviceCodeToken(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if dc.accessTokens == nil {
			t.Errorf("TestDeviceCodeToken(%s): got DeviceCode{} back that did not have accessTokens set", test.desc)
		}
	}
}

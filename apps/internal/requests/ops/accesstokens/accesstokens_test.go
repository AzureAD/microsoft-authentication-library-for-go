// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/internal/grant"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/wstrust"
	"github.com/kylelemons/godebug/pretty"
)

var testAuthorityEndpoints = authority.NewEndpoints(
	"https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com",
)

type fakeURLCaller struct {
	err bool

	gotEndpoint string
	gotQV       url.Values
	gotResp     interface{}
}

func (f *fakeURLCaller) URLFormCall(ctx context.Context, endpoint string, qv url.Values, resp interface{}) error {
	if f.err {
		return errors.New("error")
	}
	f.gotEndpoint = endpoint
	f.gotQV = qv
	f.gotResp = resp

	return nil
}

func (f *fakeURLCaller) compare(endpoint string, qv url.Values) error {
	if f.gotEndpoint != endpoint {
		return fmt.Errorf("got endpoint == %s, want endpoint == %s", f.gotEndpoint, endpoint)
	}
	if diff := pretty.Compare(qv, f.gotQV); diff != "" {
		return fmt.Errorf("qv -want/+got:\n%s", diff)
	}
	return nil
}

type fakeCreateTokenResp struct {
	err bool
}

func (f fakeCreateTokenResp) CreateTokenResp(authParameters authority.AuthParams, payload msalbase.TokenResponseJSONPayload) (accesstokens.TokenResponse, error) {
	if f.err {
		return accesstokens.TokenResponse{}, errors.New("error")
	}
	return accesstokens.TokenResponse{}, nil
}

func TestGetAccessTokenFromUsernamePassword(t *testing.T) {
	authParams := authority.AuthParams{
		Username:  "username",
		Password:  "password",
		Endpoints: testAuthorityEndpoints,
		ClientID:  "clientID",
	}

	tests := []struct {
		desc      string
		err       bool
		commErr   bool
		createErr bool
		qv        url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
		},
		{
			desc: "Success",
			qv: url.Values{
				grantType:  []string{passworGrant},
				username:   []string{authParams.Username},
				password:   []string{authParams.Password},
				clientID:   []string{authParams.ClientID},
				clientInfo: []string{clientInfoVal},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenFromUsernamePassword(context.Background(), authParams)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenFromUsernamePassword(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenFromUsernamePassword(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenFromUsernamePassword(%s): %s", test.desc, err)
		}
	}
}

func TestGetAccessTokenFromAuthCode(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc         string
		err          bool
		commErr      bool
		createErr    bool
		authCode     string
		codeVerifier string
		params       url.Values
		qv           url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			params: url.Values{
				"mine": []string{"set"},
			},
			authCode:     "authCode",
			codeVerifier: "codeVerifier",
			qv: url.Values{
				"mine":          []string{"set"},
				"code":          []string{"authCode"},
				"code_verifier": []string{"codeVerifier"},
				"redirect_uri":  []string{"redirectURI"},
				grantType:       []string{grant.AuthCode},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
		{
			desc: "Success",
			params: url.Values{
				"mine": []string{"set"},
			},
			authCode:     "authCode",
			codeVerifier: "codeVerifier",
			qv: url.Values{
				"mine":          []string{"set"},
				"code":          []string{"authCode"},
				"code_verifier": []string{"codeVerifier"},
				"redirect_uri":  []string{"redirectURI"},
				grantType:       []string{grant.AuthCode},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.err}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenFromAuthCode(context.Background(), authParams, test.authCode, test.codeVerifier, test.params)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenFromAuthCode(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenFromAuthCode(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenFromAuthCode(%s): %s", test.desc, err)
		}
	}
}

func TestGetAccessTokenFromRefreshToken(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc         string
		err          bool
		commErr      bool
		createErr    bool
		refreshToken string
		params       url.Values
		qv           url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			params: url.Values{
				"mine": []string{"set"},
			},
			refreshToken: "refreshToken",
			qv: url.Values{
				"mine":          []string{"set"},
				"refresh_token": []string{"refreshToken"},
				grantType:       []string{grant.RefreshToken},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
		{
			desc: "Success",
			params: url.Values{
				"mine": []string{"set"},
			},
			refreshToken: "refreshToken",
			qv: url.Values{
				"mine":          []string{"set"},
				"refresh_token": []string{"refreshToken"},
				grantType:       []string{grant.RefreshToken},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenFromRefreshToken(context.Background(), authParams, test.refreshToken, test.params)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenFromRefreshToken(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenFromRefreshToken(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenFromRefreshToken(%s): %s", test.desc, err)
		}
	}
}

func TestGetAccessTokenWithClientSecret(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc         string
		err          bool
		commErr      bool
		createErr    bool
		clientSecret string
		qv           url.Values
	}{
		{
			desc:         "Error: comm returns error",
			err:          true,
			commErr:      true,
			clientSecret: "clientSecret",
			qv: url.Values{
				"client_secret": []string{"clientSecret"},
				grantType:       []string{grant.ClientCredential},
				clientID:        []string{authParams.ClientID},
			},
		},
		{
			desc:         "Success",
			clientSecret: "clientSecret",
			qv: url.Values{
				"client_secret": []string{"clientSecret"},
				grantType:       []string{grant.ClientCredential},
				clientID:        []string{authParams.ClientID},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.err}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenWithClientSecret(context.Background(), authParams, test.clientSecret)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenWithClientSecret(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenWithClientSecret(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenWithClientSecret(%s): %s", test.desc, err)
		}
	}
}

func TestGetAccessTokenWithAssertion(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc      string
		err       bool
		commErr   bool
		createErr bool
		assertion string
		params    url.Values
		qv        url.Values
	}{
		{
			desc:      "Error: comm returns error",
			err:       true,
			commErr:   true,
			assertion: "assertion",
			qv: url.Values{
				"client_assertion_type": []string{grant.ClientAssertion},
				"client_assertion":      []string{"assertion"},
				grantType:               []string{grant.ClientCredential},
				clientInfo:              []string{clientInfoVal},
			},
		},
		{
			desc:      "Success",
			assertion: "assertion",
			qv: url.Values{
				"client_assertion_type": []string{grant.ClientAssertion},
				"client_assertion":      []string{"assertion"},
				grantType:               []string{grant.ClientCredential},
				clientInfo:              []string{clientInfoVal},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenWithAssertion(context.Background(), authParams, test.assertion)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenWithAssertion(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenWithAssertion(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenWithAssertion(%s): %s", test.desc, err)
		}
	}
}

func TestGetDeviceCodeResult(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc      string
		err       bool
		commErr   bool
		createErr bool
		assertion string
		params    url.Values
		qv        url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			qv: url.Values{
				clientID: []string{authParams.ClientID},
			},
		},
		{
			desc: "Success",
			qv: url.Values{
				clientID: []string{authParams.ClientID},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetDeviceCodeResult(context.Background(), authParams)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetDeviceCodeResult(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetDeviceCodeResult(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		wantEndpoint := strings.Replace(authParams.Endpoints.TokenEndpoint, "token", "devicecode", -1)
		if err := fake.compare(wantEndpoint, test.qv); err != nil {
			t.Errorf("TestGetDeviceCodeResult(%s): %s", test.desc, err)
		}
	}
}

func TestGetAccessTokenFromDeviceCodeResult(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc             string
		err              bool
		commErr          bool
		createErr        bool
		deviceCodeResult msalbase.DeviceCodeResult
		qv               url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			deviceCodeResult: msalbase.NewDeviceCodeResult(
				"userCode",
				"deviceCode",
				"verificationURL",
				time.Now(),
				1,
				"message",
				"clientID",
				nil,
			),
			qv: url.Values{
				deviceCode: []string{"deviceCode"},
				grantType:  []string{grant.DeviceCode},
				clientID:   []string{authParams.ClientID},
				clientInfo: []string{clientInfoVal},
			},
		},
		{
			desc: "Success",
			deviceCodeResult: msalbase.NewDeviceCodeResult(
				"userCode",
				"deviceCode",
				"verificationURL",
				time.Now(),
				1,
				"message",
				"clientID",
				nil,
			),
			qv: url.Values{
				deviceCode: []string{"deviceCode"},
				grantType:  []string{grant.DeviceCode},
				clientID:   []string{authParams.ClientID},
				clientInfo: []string{clientInfoVal},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenFromDeviceCodeResult(context.Background(), authParams, test.deviceCodeResult)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenFromDeviceCodeResult(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenFromDeviceCodeResult(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenFromDeviceCodeResult(%s): %s", test.desc, err)
		}
	}
}

func TestGetAccessTokenFromSamlGrant(t *testing.T) {
	authParams := authority.AuthParams{
		Username:  "username",
		Password:  "password",
		Endpoints: testAuthorityEndpoints,
		ClientID:  "clientID",
	}
	base64Assertion := base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString([]byte("assertion"))

	tests := []struct {
		desc      string
		err       bool
		commErr   bool
		createErr bool
		samlGrant wstrust.SamlTokenInfo
		qv        url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			samlGrant: wstrust.SamlTokenInfo{
				AssertionType: grant.SAMLV1,
				Assertion:     "assertion",
			},
			qv: url.Values{
				username:    []string{"username"},
				password:    []string{"password"},
				grantType:   []string{grant.SAMLV1},
				clientID:    []string{authParams.ClientID},
				clientInfo:  []string{clientInfoVal},
				"assertion": []string{base64Assertion},
			},
		},
		{
			desc: "Error: unknown grant type(empty space)",
			err:  true,
			samlGrant: wstrust.SamlTokenInfo{
				Assertion: "assertion",
			},
			qv: url.Values{
				username:    []string{"username"},
				password:    []string{"password"},
				grantType:   []string{grant.SAMLV1},
				clientID:    []string{authParams.ClientID},
				clientInfo:  []string{clientInfoVal},
				"assertion": []string{base64Assertion},
			},
		},
		{
			desc: "Success: SAMLV1Grant",
			samlGrant: wstrust.SamlTokenInfo{
				AssertionType: grant.SAMLV1,
				Assertion:     "assertion",
			},
			qv: url.Values{
				username:    []string{"username"},
				password:    []string{"password"},
				grantType:   []string{grant.SAMLV1},
				clientID:    []string{authParams.ClientID},
				clientInfo:  []string{clientInfoVal},
				"assertion": []string{base64Assertion},
			},
		},
		{
			desc: "Success: SAMLV2Grant",
			samlGrant: wstrust.SamlTokenInfo{
				AssertionType: grant.SAMLV2,
				Assertion:     "assertion",
			},
			qv: url.Values{
				username:    []string{"username"},
				password:    []string{"password"},
				grantType:   []string{grant.SAMLV2},
				clientID:    []string{authParams.ClientID},
				clientInfo:  []string{clientInfoVal},
				"assertion": []string{base64Assertion},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAccessTokenFromSamlGrant(context.Background(), authParams, test.samlGrant)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetAccessTokenFromSamlGrant(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetAccessTokenFromSamlGrant(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestGetAccessTokenFromSamlGrant(%s): %s", test.desc, err)
		}
	}
}

func TestDecodeJWT(t *testing.T) {
	encodedStr := "aGVsbG8"
	expectedStr := []byte("hello")
	actualString, err := decodeJWT(encodedStr)
	if err != nil {
		t.Errorf("Error should be nil but it is %v", err)
	}
	if !reflect.DeepEqual(expectedStr, actualString) {
		t.Errorf("Actual decoded string %s differs from expected decoded string %s", actualString, expectedStr)
	}
}

func TestGetLocalAccountID(t *testing.T) {
	id := &IDToken{
		Subject: "sub",
	}
	actualLID := id.GetLocalAccountID()
	if !reflect.DeepEqual("sub", actualLID) {
		t.Errorf("Expected local account ID sub differs from actual local account ID %s", actualLID)
	}
	id.Oid = "oid"
	actualLID = id.GetLocalAccountID()
	if !reflect.DeepEqual("oid", actualLID) {
		t.Errorf("Expected local account ID oid differs from actual local account ID %s", actualLID)
	}
}

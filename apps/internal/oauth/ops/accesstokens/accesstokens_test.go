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

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"
	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/internal/grant"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust"

	"github.com/kylelemons/godebug/pretty"
)

var testAuthorityEndpoints = authority.NewEndpoints(
	"https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com",
)

var jwtDecoderFake = func(s string) ([]byte, error) {
	if s == "error" {
		return nil, errors.New("error")
	}
	return []byte(s), nil
}

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

func TestAccessTokenFromUsernamePassword(t *testing.T) {
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
				grantType:  []string{grant.Password},
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromUsernamePassword(context.Background(), authParams)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAccessTokenFromUsernamePassword(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAccessTokenFromUsernamePassword(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestAccessTokenFromUsernamePassword(%s): %s", test.desc, err)
		}
	}
}

func TestAccessTokenFromAuthCode(t *testing.T) {
	authParams := authority.AuthParams{
		Endpoints:   testAuthorityEndpoints,
		ClientID:    "clientID",
		Redirecturi: "redirectURI",
	}

	tests := []struct {
		desc string
		err  bool
		// commErr causes the comm call to return an error.
		commErr bool
		// createErr causes the TokenResponse creation to error.
		createErr       bool
		authCodeRequest AuthCodeRequest
		authCode        string
		codeVerifier    string
		qv              url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			authCodeRequest: AuthCodeRequest{
				AuthParams:    authParams,
				Code:          "authCode",
				CodeChallenge: "codeVerifier",
				Credential:    &Credential{Secret: "secret"},
				AppType:       ATConfidential,
			},
			qv: url.Values{
				"code":          []string{"authCode"},
				"code_verifier": []string{"codeVerifier"},
				"redirect_uri":  []string{"redirectURI"},
				grantType:       []string{grant.AuthCode},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
		{
			desc: "Error: Credential is nil",
			authCodeRequest: AuthCodeRequest{
				AuthParams:    authParams,
				Code:          "authCode",
				CodeChallenge: "codeVerifier",
				AppType:       ATConfidential,
			},
			qv: url.Values{
				"code":          []string{"authCode"},
				"code_verifier": []string{"codeVerifier"},
				"redirect_uri":  []string{"redirectURI"},
				grantType:       []string{grant.AuthCode},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
			err: true,
		},
		{
			desc: "Success",
			authCodeRequest: AuthCodeRequest{
				AuthParams:    authParams,
				Code:          "authCode",
				CodeChallenge: "codeVerifier",
				AppType:       ATConfidential,
				Credential:    &Credential{Secret: "secret"},
			},
			qv: url.Values{
				"code":          []string{"authCode"},
				"code_verifier": []string{"codeVerifier"},
				"redirect_uri":  []string{"redirectURI"},
				"client_secret": []string{"secret"},
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromAuthCode(context.Background(), test.authCodeRequest)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAccessTokenFromAuthCode(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAccessTokenFromAuthCode(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestAccessTokenFromAuthCode(%s): %s", test.desc, err)
		}
	}
}

func TestAccessTokenFromRefreshToken(t *testing.T) {
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
		cred         *Credential
		refreshToken string
		qv           url.Values
	}{
		{
			desc:         "Error: comm returns error",
			err:          true,
			commErr:      true,
			refreshToken: "refreshToken",
			qv: url.Values{
				"refresh_token": []string{"refreshToken"},
				grantType:       []string{grant.RefreshToken},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
		{
			desc:         "Success(public app)",
			refreshToken: "refreshToken",
			qv: url.Values{
				"refresh_token": []string{"refreshToken"},
				grantType:       []string{grant.RefreshToken},
				clientID:        []string{authParams.ClientID},
				clientInfo:      []string{clientInfoVal},
			},
		},
		{
			desc:         "Success(confidential app)",
			refreshToken: "refreshToken",
			qv: url.Values{
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromRefreshToken(context.Background(), ATPublic, authParams, test.cred, test.refreshToken)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAccessTokenFromRefreshToken(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAccessTokenFromRefreshToken(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestAccessTokenFromRefreshToken(%s): %s", test.desc, err)
		}
	}
}

func TestAccessTokenWithClientSecret(t *testing.T) {
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromClientSecret(context.Background(), authParams, test.clientSecret)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAccessTokenWithClientSecret(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAccessTokenWithClientSecret(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestAccessTokenWithClientSecret(%s): %s", test.desc, err)
		}
	}
}

func TestAccessTokenWithAssertion(t *testing.T) {
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
				clientID:                []string{authParams.ClientID},
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
				clientID:                []string{authParams.ClientID},
			},
		},
	}

	for _, test := range tests {
		if test.qv != nil {
			addScopeQueryParam(test.qv, authParams)
		}

		fake := &fakeURLCaller{err: test.commErr}
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromAssertion(context.Background(), authParams, test.assertion)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAccessTokenWithAssertion(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAccessTokenWithAssertion(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestAccessTokenWithAssertion(%s): %s", test.desc, err)
		}
	}
}

func TestDeviceCodeResult(t *testing.T) {
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.DeviceCodeResult(context.Background(), authParams)
		switch {
		case err == nil && test.err:
			t.Errorf("TestDeviceCodeResult(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestDeviceCodeResult(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		wantEndpoint := strings.Replace(authParams.Endpoints.TokenEndpoint, "token", "devicecode", -1)
		if err := fake.compare(wantEndpoint, test.qv); err != nil {
			t.Errorf("TestDeviceCodeResult(%s): %s", test.desc, err)
		}
	}
}

func TestFromDeviceCodeResult(t *testing.T) {
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
		deviceCodeResult DeviceCodeResult
		qv               url.Values
	}{
		{
			desc:    "Error: comm returns error",
			err:     true,
			commErr: true,
			deviceCodeResult: NewDeviceCodeResult(
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
			deviceCodeResult: NewDeviceCodeResult(
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromDeviceCodeResult(context.Background(), authParams, test.deviceCodeResult)
		switch {
		case err == nil && test.err:
			t.Errorf("TestFromDeviceCodeResult(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestFromDeviceCodeResult(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestFromDeviceCodeResult(%s): %s", test.desc, err)
		}
	}
}

func TestAccessTokenFromSamlGrant(t *testing.T) {
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
		client := Client{Comm: fake, testing: true}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromSamlGrant(context.Background(), authParams, test.samlGrant)
		switch {
		case err == nil && test.err:
			t.Errorf("TestAccessTokenFromSamlGrant(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestAccessTokenFromSamlGrant(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(authParams.Endpoints.TokenEndpoint, test.qv); err != nil {
			t.Errorf("TestAccessTokenFromSamlGrant(%s): %s", test.desc, err)
		}
	}
}

func TestDecodeJWT(t *testing.T) {
	encodedStr := "A-z_4ME"
	expectedStr := []byte{3, 236, 255, 224, 193}
	actualString, err := decodeJWT(encodedStr)
	if err != nil {
		t.Errorf("Error should be nil but it is %v", err)
	}
	if !reflect.DeepEqual(expectedStr, actualString) {
		t.Errorf("Actual decoded string %s differs from expected decoded string %s", actualString, expectedStr)
	}
}

func TestLocalAccountID(t *testing.T) {
	id := &IDToken{
		Subject: "sub",
	}
	actualLID := id.LocalAccountID()
	if !reflect.DeepEqual("sub", actualLID) {
		t.Errorf("Expected local account ID sub differs from actual local account ID %s", actualLID)
	}
	id.Oid = "oid"
	actualLID = id.LocalAccountID()
	if !reflect.DeepEqual("oid", actualLID) {
		t.Errorf("Expected local account ID oid differs from actual local account ID %s", actualLID)
	}
}

func TestTokenResponseUnmarshal(t *testing.T) {
	tests := []struct {
		desc       string
		payload    string
		want       TokenResponse
		jwtDecoder func(data string) ([]byte, error)
		err        bool
	}{
		{
			desc: "Error: decodeJWT is going to error",
			payload: `
				{
					"access_token": "secret",
					"expires_in": 86399,
					"ext_expires_in": 86399,
					"client_info": error,
					"scope": "openid profile"
				}`,
			err:        true,
			jwtDecoder: jwtDecoderFake,
		},
		{
			desc: "Success",
			payload: `
				{
					"access_token": "secret",
					"expires_in": 86399,
					"ext_expires_in": 86399,
					"client_info": {"uid":  "uid","utid": "utid"},
					"scope": "openid profile"
				}`,
			want: TokenResponse{
				AccessToken:   "secret",
				ExpiresOn:     internalTime.DurationTime{T: time.Unix(86399, 0)},
				ExtExpiresOn:  internalTime.DurationTime{T: time.Unix(86399, 0)},
				GrantedScopes: Scopes{Slice: []string{"openid", "profile"}},
				ClientInfo: ClientInfo{
					UID:  "uid",
					UTID: "utid",
				},
			},
			jwtDecoder: jwtDecoderFake,
		},
	}

	for _, test := range tests {
		jwtDecoder = test.jwtDecoder

		got := TokenResponse{}
		err := json.Unmarshal([]byte(test.payload), &got)
		switch {
		case err == nil && test.err:
			t.Errorf("TestCreateTokenResponse(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestCreateTokenResponse(%s): got err == %v, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		// Note: IncludeUnexported prevents minor differences in time.Time due to internal fields.
		if diff := (&pretty.Config{IncludeUnexported: false}).Compare(test.want, got); diff != "" {
			t.Errorf("TestCreateTokenResponse: -want/+got:\n%s", diff)
		}
	}
}

func TestTokenResponseValidate(t *testing.T) {
	tests := []struct {
		desc  string
		input TokenResponse
		err   bool
	}{
		{
			desc: "Error: TokenResponse had .Error set",
			input: TokenResponse{
				OAuthResponseBase: authority.OAuthResponseBase{
					Error: "error",
				},
				AccessToken:    "token",
				scopesComputed: true,
			},
			err: true,
		},
		{
			desc: "Error: .AccessToken was empty",
			input: TokenResponse{
				scopesComputed: true,
			},
			err: true,
		},
		{
			desc: "Error: .scopesComputed was false",
			input: TokenResponse{
				AccessToken:    "token",
				scopesComputed: false,
			},
			err: true,
		},
		{
			desc: "Success",
			input: TokenResponse{
				AccessToken:    "token",
				scopesComputed: true,
			},
		},
	}

	for _, test := range tests {
		err := test.input.Validate()
		switch {
		case err == nil && test.err:
			t.Errorf("TestTokenResponseValidate(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestTokenResponseValidate(%s): got err == %s, want err == nil", test.desc, err)
		}
	}
}

func TestComputeScopes(t *testing.T) {
	tests := []struct {
		desc       string
		authParams authority.AuthParams
		input      TokenResponse
		want       TokenResponse
	}{
		{
			desc: "authParam scopes copied in, no declined scopes",
			authParams: authority.AuthParams{
				Scopes: []string{
					"scope0",
					"scope1",
				},
			},
			input: TokenResponse{},
			want: TokenResponse{
				GrantedScopes: Scopes{
					Slice: []string{"scope0", "scope1"},
				},
				scopesComputed: true,
			},
		},
		{
			desc: "a few declined scopes",
			authParams: authority.AuthParams{
				Scopes: []string{
					"scope0",
					"scope1",
					"scope2",
				},
			},
			input: TokenResponse{
				GrantedScopes: Scopes{
					Slice: []string{
						"scope0",
						"scope1",
					},
				},
			},
			want: TokenResponse{
				GrantedScopes: Scopes{
					Slice: []string{"scope0", "scope1"},
				},
				DeclinedScopes: []string{"scope2"},
				scopesComputed: true,
			},
		},
		{
			desc: "no declined scopes case insensitive",
			authParams: authority.AuthParams{
				Scopes: []string{
					"scope0",
					"scope1",
				},
			},
			input: TokenResponse{
				GrantedScopes: Scopes{
					Slice: []string{
						"Scope0",
						"Scope1",
					},
				},
			},
			want: TokenResponse{
				GrantedScopes: Scopes{
					Slice: []string{"Scope0", "Scope1"},
				},
				DeclinedScopes: nil,
				scopesComputed: true,
			},
		},
	}

	for _, test := range tests {
		test.input.ComputeScope(test.authParams)
		if diff := pretty.Compare(test.want, test.input); diff != "" {
			t.Errorf("TestComputeScopes(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}

func TestHomeAccountID(t *testing.T) {
	tests := []struct {
		desc string
		ci   ClientInfo
		want string
	}{
		{
			desc: "UID and UTID is not set",
		},
		{
			desc: "UID is not set",
			ci:   ClientInfo{UTID: "utid"},
		},
		{
			desc: "UTID is not set",
			ci:   ClientInfo{UID: "uid"},
			want: "uid.uid",
		},
		{
			desc: "UID and UTID are set",
			ci:   ClientInfo{UID: "uid", UTID: "utid"},
			want: "uid.utid",
		},
	}

	for _, test := range tests {
		got := test.ci.HomeAccountID()
		if got != test.want {
			t.Errorf("TestHomeAccountID(%s): got %q, want %q", test.desc, got, test.want)
		}
	}
}

func TestFindDeclinedScopes(t *testing.T) {
	requestedScopes := []string{"user.read", "openid"}
	grantedScopes := []string{"user.read"}
	expectedDeclinedScopes := []string{"openid"}
	actualDeclinedScopes := findDeclinedScopes(requestedScopes, grantedScopes)
	if !reflect.DeepEqual(expectedDeclinedScopes, actualDeclinedScopes) {
		t.Errorf("Actual declined scopes %v differ from expected declined scopes %v", actualDeclinedScopes, expectedDeclinedScopes)
	}
}

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

func (f fakeCreateTokenResp) CreateTokenResp(authParameters authority.AuthParams, payload TokenResponseJSONPayload) (TokenResponse, error) {
	if f.err {
		return TokenResponse{}, errors.New("error")
	}
	return TokenResponse{}, nil
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
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromUsernamePassword(context.Background(), authParams)
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
				RequestType:   AuthCodeConfidential,
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
				RequestType:   AuthCodeConfidential,
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
				RequestType:   AuthCodeConfidential,
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
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromAuthCode(context.Background(), test.authCodeRequest)
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
		/*
			{
				desc: "Success(confidential app)",
				refreshToken: "refreshToken",
				qv: url.Values{
					"refresh_token": []string{"refreshToken"},
					grantType:       []string{grant.RefreshToken},
					clientID:        []string{authParams.ClientID},
					clientInfo:      []string{clientInfoVal},
				},
			},
		*/
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
		_, err := client.FromRefreshToken(context.Background(), RefreshTokenPublic, authParams, test.cred, test.refreshToken)
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
		_, err := client.FromClientSecret(context.Background(), authParams, test.clientSecret)
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
		_, err := client.FromAssertion(context.Background(), authParams, test.assertion)
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
		_, err := client.DeviceCodeResult(context.Background(), authParams)
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
		fakeCreate := fakeCreateTokenResp{test.createErr}
		client := Client{Comm: fake, TokenRespFunc: fakeCreate.CreateTokenResp}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.FromDeviceCodeResult(context.Background(), authParams, test.deviceCodeResult)
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
		_, err := client.FromSamlGrant(context.Background(), authParams, test.samlGrant)
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

func TestCreateTokenResponse(t *testing.T) {
	authParams := authority.AuthParams{
		Scopes: []string{"openid", "profile"},
	}

	tests := []struct {
		desc    string
		payload TokenResponseJSONPayload
		want    TokenResponse
		err     bool
	}{
		{
			desc: "Error: JSON response had error(no AccessToken set)",
			payload: TokenResponseJSONPayload{
				ExpiresIn:    86399,
				ExtExpiresIn: 86399,
			},
			err: true,
		},
		{
			desc: "Success",
			payload: TokenResponseJSONPayload{
				AccessToken:  "secret",
				ExpiresIn:    86399,
				ExtExpiresIn: 86399,
			},
			want: TokenResponse{
				AccessToken:   "secret",
				ExpiresOn:     time.Unix(86399, 0),
				ExtExpiresOn:  time.Unix(86399, 0),
				GrantedScopes: []string{"openid", "profile"},
				ClientInfo:    ClientInfoJSONPayload{},
			},
		},
	}

	for _, test := range tests {
		got, err := NewTokenResponse(authParams, test.payload)
		switch {
		case err == nil && test.err:
			t.Errorf("TestCreateTokenResponse(%s): got err == nil, want err != nil", test.desc)
		case err != nil && !test.err:
			t.Errorf("TestCreateTokenResponse(%s): got err == %v, want err == nil", test.desc, err)
		case err != nil:
			continue
		}

		// Note: IncludeUnexported prevents minor differences in time.Time due to internal fields.
		if diff := (&pretty.Config{IncludeUnexported: false}).Compare(test.want, got); diff != "" {
			t.Errorf("TestCreateTokenResponse: -want/+got:\n%s", diff)
		}
	}
}

func TestGetHomeAccountIDFromClientInfo(t *testing.T) {
	clientInfo := ClientInfoJSONPayload{
		UID:  "uid",
		Utid: "utid",
	}
	tokenResponse := TokenResponse{ClientInfo: clientInfo}
	expectedHid := "uid.utid"
	actualHid := tokenResponse.GetHomeAccountIDFromClientInfo()
	if !reflect.DeepEqual(actualHid, expectedHid) {
		t.Errorf("Actual home account ID %s differs from expected home account ID %s", actualHid, expectedHid)
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

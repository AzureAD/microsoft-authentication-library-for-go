// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

/*
type fakeManager struct {
	manager // embed the interface to prevent changes breaking it

	trcErr, ctrErr bool
}

func (f *fakeManager) Read(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (msalbase.StorageTokenResponse, error) {
	if f.trcErr {
		return msalbase.StorageTokenResponse{}, errors.New("error")
	}

	at := new(msalbase.MockAccessToken)
	rt := new(msalbase.MockCredential)
	id := new(msalbase.MockCredential)
	at.On("GetSecret").Return("secret")
	at.On("GetExpiresOn").Return("0")
	at.On("GetScopes").Return("openid")
	rt.On("GetSecret").Return("secret")
	id.On("GetSecret").Return("secret")

	return storage.NewStorageTokenResponse(at, rt, id, msalbase.Account{}), nil
}

func (f *fakeManager) Write(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error) {
	if f.ctrErr {
		return msalbase.Account{}, errors.New("error")
	}

	return msalbase.Account{}, nil
}

func newTestApplication(fm *fakeManager, wrm *requests.MockWebRequestManager) *clientApplication {
	return &clientApplication{
		clientApplicationParameters: &clientApplicationParameters{
			commonParameters: &applicationCommonParameters{
				clientID:      "clientID",
				authorityInfo: testAuthorityInfo,
			},
		},
		webRequestManager: wrm,
		manager:           fm,
		cacheAccessor:     noopCacheAccessor{},
	}
}

// TODO(MSAL expert): These tests are bogus or missing important details.  Here are notes:
// TestAcquireTokenSilent: should be table driven and should change fakeManager or MockWebRequestManager
// to test various error states.  As is, tests a single positive state.
// TestExecuteTokenRequestWithoutCacheWrite/TestExecuteTokenRequestWithCacheWrite actually don't test
// those methods. They test that they error, which is a weird thing to test. Should test error and non error
// states using table driven tests.
func TestAcquireTokenSilent(t *testing.T) {
	silentParams := AcquireTokenSilentParameters{
		commonParameters: tokenCommonParams,
		account:          msalbase.Account{},
	}
	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}
	app := newTestApplication(fm, wrm)

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	wrm.On(
		"GetAccessTokenFromRefreshToken",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
		"secret",
		url.Values{},
	).Return(msalbase.TokenResponse{}, nil)

	_, err := app.acquireTokenSilent(context.Background(), silentParams)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestExecuteTokenRequestWithoutCacheWrite(t *testing.T) {
	app := newTestApplication(nil, nil)

	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	req := new(requests.MockTokenRequest)
	actualTokenResp := msalbase.TokenResponse{}
	req.On("Execute").Return(actualTokenResp, nil)
	_, err := app.executeTokenRequestWithoutCacheWrite(context.Background(), req, testAuthParams)
	if err != nil {
		t.Fatalf("Error should be nil, instead it is %v", err)
	}
	mockError := errors.New("This is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(msalbase.TokenResponse{}, mockError)
	_, err = app.executeTokenRequestWithoutCacheWrite(context.Background(), errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}

func TestExecuteTokenRequestWithCacheWrite(t *testing.T) {
	app := newTestApplication(nil, nil)

	testAuthParams := msalbase.CreateAuthParametersInternal("clientID", testAuthorityInfo)
	mockError := errors.New("this is a mock error")
	errorReq := new(requests.MockTokenRequest)
	errorReq.On("Execute").Return(msalbase.TokenResponse{}, mockError)
	_, err := app.executeTokenRequestWithCacheWrite(context.Background(), errorReq, testAuthParams)
	if err != mockError {
		t.Errorf("Actual error is %v, expected error is %v", err, mockError)
	}
}

func TestAcquireTokenByClientCredential(t *testing.T) {
	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}

	cred, _ := msalbase.CreateClientCredentialFromSecret("client_secret")
	cca := &ConfidentialClientApplication{
		clientApplication: newTestApplication(fm, wrm),
		clientCredential:  cred,
	}

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)

	wrm.On(
		"GetAccessTokenWithClientSecret",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
		"client_secret",
	).Return(msalbase.TokenResponse{}, nil)

	_, err := cca.AcquireTokenByClientCredential(context.Background(), []string{"openid"})
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

// TODO(jdoak): Remove all of these globals.
var tokenCommonParams = acquireTokenCommonParameters{
	scopes: []string{"openid"},
}
var testAuthorityEndpoints = msalbase.CreateAuthorityEndpoints("https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com")
var testAuthorityInfo, _ = msalbase.CreateAuthorityInfoFromAuthorityURI("https://login.microsoftonline.com/v2.0/", true)

var tdr = requests.TenantDiscoveryResponse{
	AuthorizationEndpoint: "https://login.microsoftonline.com/v2.0/authorize",
	TokenEndpoint:         "https://login.microsoftonline.com/v2.0/token",
	Issuer:                "https://login.microsoftonline.com/v2.0",
}

func TestCreateAuthCodeURL(t *testing.T) {
	authCodeURLParams := CreateAuthorizationCodeURLParameters("clientID", "redirect", []string{"openid"})
	authCodeURLParams.CodeChallenge = "codeChallenge"

	wrm := new(requests.MockWebRequestManager)
	testPCA := &PublicClientApplication{
		clientApplication: newTestApplication(nil, wrm),
	}

	wrm.On("GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)

	url, err := testPCA.CreateAuthCodeURL(context.Background(), authCodeURLParams)
	if err != nil {
		t.Fatalf("Error should be nil, instead it is %v", err)
	}

	actualURL := "https://login.microsoftonline.com/v2.0/authorize?client_id=clientID&code_challenge=codeChallenge" +
		"&redirect_uri=redirect&response_type=code&scope=openid"
	if actualURL != url {
		t.Errorf("URL should be %v, instead it is %v", actualURL, url)
	}
}

func TestAcquireTokenByAuthCode(t *testing.T) {
	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}

	testPCA := &PublicClientApplication{
		clientApplication: newTestApplication(fm, wrm),
	}

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)

	actualTokenResp := msalbase.TokenResponse{}
	wrm.On(
		"GetAccessTokenFromAuthCode",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
		"",
		"",
		url.Values{},
	).Return(actualTokenResp, nil)

	_, err := testPCA.AcquireTokenByAuthCode(context.Background(), []string{"openid"}, nil)
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}

func TestAcquireTokenByUsernamePassword(t *testing.T) {
	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}

	testPCA := &PublicClientApplication{
		clientApplication: newTestApplication(fm, wrm),
	}

	managedUserRealm := msalbase.UserRealm{
		AccountType: "Managed",
	}

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	wrm.On(
		"GetUserRealm",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
	).Return(managedUserRealm, nil)
	actualTokenResp := msalbase.TokenResponse{}

	wrm.On(
		"GetAccessTokenFromUsernamePassword",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
	).Return(actualTokenResp, nil)

	_, err := testPCA.AcquireTokenByUsernamePassword(context.Background(), []string{"openid"}, "username", "password")
	if err != nil {
		t.Errorf("Error should be nil, instead it is %v", err)
	}
}

func TestAcquireTokenByDeviceCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	callback := func(dcr DeviceCodeResultProvider) {}

	wrm := new(requests.MockWebRequestManager)
	fm := &fakeManager{}

	testPCA := &PublicClientApplication{
		clientApplication: newTestApplication(fm, wrm),
	}

	wrm.On(
		"GetTenantDiscoveryResponse",
		"https://login.microsoftonline.com/v2.0/v2.0/.well-known/openid-configuration",
	).Return(tdr, nil)
	actualTokenResp := msalbase.TokenResponse{}
	devCodeResp := requests.DeviceCodeResponse{ExpiresIn: 10}
	devCodeResult := devCodeResp.ToDeviceCodeResult("clientID", tokenCommonParams.scopes)
	wrm.On(
		"GetDeviceCodeResult",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
	).Return(devCodeResult, nil)
	wrm.On(
		"GetAccessTokenFromDeviceCodeResult",
		mock.AnythingOfType("msalbase.AuthParametersInternal"),
		devCodeResult,
	).Return(actualTokenResp, nil)

	_, err := testPCA.AcquireTokenByDeviceCode(ctx, []string{"openid"}, callback, nil)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}
*/

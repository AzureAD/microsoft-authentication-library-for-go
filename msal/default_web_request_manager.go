// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/wstrust"
	log "github.com/sirupsen/logrus"
)

// defaultWebRequestManager handles the HTTP calls and request building in MSAL
type defaultWebRequestManager struct {
	httpClient HTTPClient
}

func isErrorAuthorizationPending(err error) bool {
	return err.Error() == "authorization_pending"
}

func isErrorSlowDown(err error) bool {
	return err.Error() == "slow_down"
}

type contentType int

const (
	soapXMLUtf8 contentType = iota
	urlEncodedUtf8
)

func createWebRequestManager(httpClient HTTPClient) requests.WebRequestManager {
	return &defaultWebRequestManager{httpClient}
}

func (wrm *defaultWebRequestManager) GetUserRealm(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.UserRealm, error) {
	url := authParameters.Endpoints.GetUserRealmEndpoint(authParameters.Username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return msalbase.UserRealm{}, err
	}
	addAADHeaders(req.Header, authParameters)
	log.Println("GetUserRealm: ", req.URL.Scheme)
	httpManagerResponse, err := wrm.httpClient.Do(req)
	if err != nil {
		return msalbase.UserRealm{}, err
	}

	if httpManagerResponse.StatusCode != http.StatusOK {
		return msalbase.UserRealm{}, errors.New("invalid response code") // todo: need error struct here
	}

	return msalbase.CreateUserRealm(httpManagerResponse)
}

func (wrm *defaultWebRequestManager) GetMex(ctx context.Context, federationMetadataURL string) (wstrust.MexDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, federationMetadataURL, nil)
	if err != nil {
		return wstrust.MexDocument{}, err
	}
	log.Println("GetMex: ", req.URL.Scheme)
	httpManagerResponse, err := wrm.httpClient.Do(req)
	if err != nil {
		return wstrust.MexDocument{}, err
	}

	if httpManagerResponse.StatusCode != http.StatusOK {
		return wstrust.MexDocument{}, errors.New("invalid response code") // todo: need error struct here
	}

	return wstrust.CreateWsTrustMexDocument(httpManagerResponse)
}

func (wrm *defaultWebRequestManager) GetWsTrustResponse(ctx context.Context, authParameters msalbase.AuthParametersInternal, cloudAudienceURN string, endpoint wstrust.Endpoint) (wstrust.Response, error) {
	const (
		SoapActionWSTrust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
		SoapActionDefault     = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
	)
	var wsTrustRequestMessage string
	var err error

	switch authParameters.AuthorizationType {
	case msalbase.AuthorizationTypeWindowsIntegratedAuth:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageWIA(cloudAudienceURN)
	case msalbase.AuthorizationTypeUsernamePassword:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageUsernamePassword(
			cloudAudienceURN, authParameters.Username, authParameters.Password)
	default:
		return wstrust.Response{}, errors.New("unknown auth type")
	}

	if err != nil {
		return wstrust.Response{}, err
	}

	var soapAction string

	if endpoint.EndpointVersion == wstrust.Trust2005 {
		soapAction = SoapActionWSTrust2005
	} else {
		soapAction = SoapActionDefault
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL, strings.NewReader(wsTrustRequestMessage))
	if err != nil {
		return wstrust.Response{}, err
	}
	req.Header.Set("SOAPAction", soapAction)
	addContentTypeHeader(req.Header, soapXMLUtf8)

	log.Println("GetWsTrustResponse: ", req.URL.Scheme)
	response, err := wrm.httpClient.Do(req)
	if err != nil {
		return wstrust.Response{}, err
	}
	return wstrust.CreateWsTrustResponse(response)
}

func (wrm *defaultWebRequestManager) GetAccessTokenFromSamlGrant(ctx context.Context, authParameters msalbase.AuthParametersInternal, samlGrant wstrust.SamlTokenInfo) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.PasswordGrant)
	decodedQueryParams.Set("username", authParameters.Username)
	decodedQueryParams.Set("password", authParameters.Password)

	switch samlGrant.AssertionType {
	case msalbase.SAMLV1Grant:
		decodedQueryParams.Set("grant_type", msalbase.SAMLV1Grant)
	case msalbase.SAMLV2Grant:
		decodedQueryParams.Set("grant_type", msalbase.SAMLV2Grant)
	default:
		return msalbase.TokenResponse{}, fmt.Errorf("GetAccessTokenFromSamlGrant returned unknown saml assertion type: %s", samlGrant.AssertionType)
	}

	decodedQueryParams.Set("assertion", base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString([]byte(samlGrant.Assertion))) //  .EncodeToString([]byte(samlGrant.GetAssertion())) // StringUtils::Base64RFCEncodePadded(samlGrant->GetAssertion());

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetAccessTokenFromUsernamePassword(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.PasswordGrant)
	decodedQueryParams.Set("username", authParameters.Username)
	decodedQueryParams.Set("password", authParameters.Password)

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal) (msalbase.DeviceCodeResult, error) {
	decodedQueryParams := url.Values{}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)

	deviceCodeEndpoint := strings.Replace(authParameters.Endpoints.TokenEndpoint, "token", "devicecode", -1)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceCodeEndpoint, strings.NewReader(decodedQueryParams.Encode()))
	if err != nil {
		return msalbase.DeviceCodeResult{}, err
	}

	addAADHeaders(req.Header, authParameters)
	addContentTypeHeader(req.Header, urlEncodedUtf8)

	log.Println("GetDeviceCodeResult: ", req.URL.Scheme)
	response, err := wrm.httpClient.Do(req)
	if err != nil {
		return msalbase.DeviceCodeResult{}, err
	}
	dcResponse, err := requests.CreateDeviceCodeResponse(response)
	if err != nil {
		return msalbase.DeviceCodeResult{}, err
	}

	return dcResponse.ToDeviceCodeResult(authParameters.ClientID, authParameters.Scopes), nil
}

func (wrm *defaultWebRequestManager) GetAccessTokenFromDeviceCodeResult(ctx context.Context, authParameters msalbase.AuthParametersInternal, deviceCodeResult msalbase.DeviceCodeResult) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.DeviceCodeGrant)
	decodedQueryParams.Set("device_code", deviceCodeResult.GetDeviceCode())

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	addScopeQueryParam(decodedQueryParams, authParameters)

	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func addClientIDQueryParam(queryParams url.Values, authParameters msalbase.AuthParametersInternal) {
	queryParams.Set("client_id", authParameters.ClientID)
}

func addScopeQueryParam(queryParams url.Values, authParameters msalbase.AuthParametersInternal) {
	const scopeSeparator = " "

	requestedScopes := authParameters.Scopes
	// openid required to get an id token
	// offline_access required to get a refresh token
	// profile required to get the client_info field back
	requestedScopes = append(requestedScopes, "openid", "offline_access", "profile")
	queryParams.Set("scope", strings.Join(requestedScopes, scopeSeparator))
}

func addClientInfoQueryParam(queryParams url.Values) {
	queryParams.Set("client_info", "1")
}

func addRedirectURIQueryParam(queryParams url.Values, authParameters msalbase.AuthParametersInternal) {
	queryParams.Set("redirect_uri", authParameters.Redirecturi)
}

func addContentTypeHeader(headers http.Header, contentType contentType) {
	contentTypeKey := "Content-Type"
	switch contentType {
	case soapXMLUtf8:
		headers.Set(contentTypeKey, "application/soap+xml; charset=utf-8")
		return

	case urlEncodedUtf8:
		headers.Set(contentTypeKey, "application/x-www-form-urlencoded; charset=utf-8")
		return
	}
}

const (
	// HTTP Headers.
	ProductHeaderName                    = "x-client-SKU"
	ProductHeaderValue                   = "MSAL.Go"
	OSHeaderName                         = "x-client-OS"
	CorrelationIDHeaderName              = "client-request-id"
	ReqCorrelationIDInResponseHeaderName = "return-client-request-id"
)

func addAADHeaders(headers http.Header, authParameters msalbase.AuthParametersInternal) {
	headers.Set(ProductHeaderName, ProductHeaderValue)
	headers.Set(OSHeaderName, runtime.GOOS)
	// headers["x-client-Ver"] = todo: client version here;
	headers.Set(CorrelationIDHeaderName, authParameters.CorrelationID)
	headers.Set(ReqCorrelationIDInResponseHeaderName, "false")
}

func (wrm *defaultWebRequestManager) exchangeGrantForToken(ctx context.Context, authParameters msalbase.AuthParametersInternal, queryParams url.Values) (msalbase.TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authParameters.Endpoints.TokenEndpoint, strings.NewReader(queryParams.Encode()))
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	addAADHeaders(req.Header, authParameters)
	addContentTypeHeader(req.Header, urlEncodedUtf8)

	log.Println("exchangeGrantForToken: ", req.URL.Scheme)
	response, err := wrm.httpClient.Do(req)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	return msalbase.CreateTokenResponse(authParameters, response)
}

func (wrm *defaultWebRequestManager) GetAccessTokenFromAuthCode(ctx context.Context, authParameters msalbase.AuthParametersInternal, authCode, codeVerifier string, params url.Values) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.AuthCodeGrant)
	decodedQueryParams.Set("code", authCode)
	decodedQueryParams.Set("code_verifier", codeVerifier)
	for k, v := range params {
		decodedQueryParams[k] = v
	}
	addRedirectURIQueryParam(decodedQueryParams, authParameters)
	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetAccessTokenFromRefreshToken(ctx context.Context, authParameters msalbase.AuthParametersInternal, refreshToken string, params url.Values) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.RefreshTokenGrant)
	decodedQueryParams.Set("refresh_token", refreshToken)
	for k, v := range params {
		decodedQueryParams[k] = v
	}
	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetAccessTokenWithClientSecret(ctx context.Context, authParameters msalbase.AuthParametersInternal, clientSecret string) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.ClientCredentialGrant)
	decodedQueryParams.Set("client_secret", clientSecret)
	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetAccessTokenWithAssertion(ctx context.Context, authParameters msalbase.AuthParametersInternal, assertion string) (msalbase.TokenResponse, error) {
	decodedQueryParams := url.Values{}
	decodedQueryParams.Set("grant_type", msalbase.ClientCredentialGrant)
	decodedQueryParams.Set("client_assertion_type", msalbase.ClientAssertionGrant)
	decodedQueryParams.Set("client_assertion", assertion)

	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	return wrm.exchangeGrantForToken(ctx, authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (requests.InstanceDiscoveryResponse, error) {
	queryParams := url.Values{}
	queryParams.Set("api-version", "1.1")
	queryParams.Set("authorization_endpoint", fmt.Sprintf(msalbase.AuthorizationEndpoint, authorityInfo.Host, authorityInfo.Tenant))

	discoveryHost := msalbase.DefaultHost
	if requests.IsInTrustedHostList(authorityInfo.Host) {
		discoveryHost = authorityInfo.Host
	}

	instanceDiscoveryEndpoint := fmt.Sprintf(msalbase.InstanceDiscoveryEndpoint, discoveryHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, instanceDiscoveryEndpoint, nil)
	if err != nil {
		return requests.InstanceDiscoveryResponse{}, err
	}
	req.URL.RawQuery = queryParams.Encode()
	log.Println("GetAad...: ", req.URL.Scheme)
	httpManagerResponse, err := wrm.httpClient.Do(req)
	if err != nil {
		return requests.InstanceDiscoveryResponse{}, err
	}

	if httpManagerResponse.StatusCode != http.StatusOK {
		return requests.InstanceDiscoveryResponse{}, errors.New("invalid response code") // todo: need error struct here
	}

	return requests.CreateInstanceDiscoveryResponse(httpManagerResponse)
}

func (wrm *defaultWebRequestManager) GetTenantDiscoveryResponse(ctx context.Context, openIDConfigurationEndpoint string) (requests.TenantDiscoveryResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openIDConfigurationEndpoint, nil)
	if err != nil {
		return requests.TenantDiscoveryResponse{}, err
	}
	log.Println("GetTenant...: ", req.URL.Scheme)
	httpManagerResponse, err := wrm.httpClient.Do(req)
	if err != nil {
		return requests.TenantDiscoveryResponse{}, err
	}

	return requests.CreateTenantDiscoveryResponse(httpManagerResponse)
}

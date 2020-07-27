// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/wstrust"
)

// WebRequestManager stuff
type WebRequestManager struct {
	httpManager IHTTPManager
}

func isErrorAuthorizationPending(err error) bool {
	return err.Error() == "authorization_pending"
}

func isErrorSlowDown(err error) bool {
	return err.Error() == "slow_down"
}

// ContentType stuff
type ContentType int

const (
	// SoapXMLUtf8 stuff
	SoapXMLUtf8 ContentType = iota
	// URLEncodedUtf8 stuff
	URLEncodedUtf8
)

// CreateWebRequestManager stuff
func CreateWebRequestManager(httpManager IHTTPManager) requests.IWebRequestManager {
	m := &WebRequestManager{httpManager}
	return m
}

// GetUserRealm stuff
func (wrm *WebRequestManager) GetUserRealm(authParameters *msalbase.AuthParametersInternal) (*msalbase.UserRealm, error) {
	log.Trace("GetUserRealm entered")
	url := authParameters.Endpoints.GetUserRealmEndpoint(authParameters.Username)

	log.Trace("user realm endpoint: " + url)
	httpManagerResponse, err := wrm.httpManager.Get(url, getAadHeaders(authParameters))
	if err != nil {
		return nil, err
	}

	if httpManagerResponse.GetResponseCode() != 200 {
		return nil, errors.New("invalid response code") // todo: need error struct here
	}

	return msalbase.CreateUserRealm(httpManagerResponse.GetResponseData())
}

// GetMex stuff
func (wrm *WebRequestManager) GetMex(federationMetadataURL string) (*wstrust.WsTrustMexDocument, error) {
	httpManagerResponse, err := wrm.httpManager.Get(federationMetadataURL, nil)
	if err != nil {
		return nil, err
	}

	if httpManagerResponse.GetResponseCode() != 200 {
		return nil, errors.New("invalid response code") // todo: need error struct here
	}

	return wstrust.CreateWsTrustMexDocument(httpManagerResponse.GetResponseData())
}

// GetWsTrustResponse stuff
func (wrm *WebRequestManager) GetWsTrustResponse(
	authParameters *msalbase.AuthParametersInternal,
	cloudAudienceURN string,
	endpoint *wstrust.WsTrustEndpoint) (*wstrust.WsTrustResponse, error) {
	var wsTrustRequestMessage string
	var err error

	switch authParameters.AuthorizationType {
	case msalbase.AuthorizationTypeWindowsIntegratedAuth:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageWIA(cloudAudienceURN)
	case msalbase.AuthorizationTypeUsernamePassword:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageUsernamePassword(
			cloudAudienceURN, authParameters.Username, authParameters.Password)
	default:
		log.Error("unknown auth type!")
		err = errors.New("Unknown auth type")
	}

	if err != nil {
		return nil, err
	}

	var soapAction string

	// todo: make consts out of these strings
	if endpoint.EndpointVersion == wstrust.Trust2005 {
		soapAction = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
	} else {
		soapAction = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
	}

	headers := map[string]string{
		"SOAPAction": soapAction,
	}

	addContentTypeHeader(headers, SoapXMLUtf8)

	response, err := wrm.httpManager.Post(endpoint.URL, wsTrustRequestMessage, headers)
	if err != nil {
		return nil, err
	}

	return wstrust.CreateWsTrustResponse(response.GetResponseData()), nil
}

// GetAccessTokenFromSamlGrant stuff
func (wrm *WebRequestManager) GetAccessTokenFromSamlGrant(authParameters *msalbase.AuthParametersInternal, samlGrant *wstrust.SamlTokenInfo) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type": "password",
		"username":   authParameters.Username,
		"password":   authParameters.Password,
	}

	switch samlGrant.AssertionType {
	case wstrust.SamlV1:
		decodedQueryParams["grant_type"] = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
		break
	case wstrust.SamlV2:
		decodedQueryParams["grant_type"] = "urn:ietf:params:oauth:grant-type:saml2-bearer"
		break
	default:
		return nil, errors.New("GetAccessTokenFromSamlGrant returned unknown saml assertion type: " + string(samlGrant.AssertionType))
	}

	decodedQueryParams["assertion"] = base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString([]byte(samlGrant.Assertion)) //  .EncodeToString([]byte(samlGrant.GetAssertion())) // StringUtils::Base64RFCEncodePadded(samlGrant->GetAssertion());

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAccessTokenFromUsernamePassword stuff
func (wrm *WebRequestManager) GetAccessTokenFromUsernamePassword(
	authParameters *msalbase.AuthParametersInternal) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type": "password",
		"username":   authParameters.Username,
		"password":   authParameters.Password,
	}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	log.Info(decodedQueryParams)
	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetDeviceCodeResult stuff
func (wrm *WebRequestManager) GetDeviceCodeResult(authParameters *msalbase.AuthParametersInternal) (*msalbase.DeviceCodeResult, error) {
	decodedQueryParams := map[string]string{}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)

	deviceCodeEndpoint := strings.Replace(authParameters.Endpoints.TokenEndpoint, "token", "devicecode", -1)

	headers := getAadHeaders(authParameters)
	addContentTypeHeader(headers, URLEncodedUtf8)

	response, err := wrm.httpManager.Post(
		deviceCodeEndpoint, encodeQueryParameters(decodedQueryParams), headers)
	if err != nil {
		return nil, err
	}
	dcResponse, err := requests.CreateDeviceCodeResponse(response.GetResponseCode(), response.GetResponseData())
	if err != nil {
		return nil, err
	}

	return dcResponse.ToDeviceCodeResult(authParameters.ClientID, authParameters.Scopes), nil
}

// GetAccessTokenFromDeviceCodeResult stuff
func (wrm *WebRequestManager) GetAccessTokenFromDeviceCodeResult(authParameters *msalbase.AuthParametersInternal, deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":  "device_code",
		"device_code": deviceCodeResult.GetDeviceCode(),
	}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	addScopeQueryParam(decodedQueryParams, authParameters)

	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// addClientIdQueryParam stuff
func addClientIDQueryParam(queryParams map[string]string, authParameters *msalbase.AuthParametersInternal) {
	queryParams["client_id"] = authParameters.ClientID
}

func addScopeQueryParam(queryParams map[string]string, authParameters *msalbase.AuthParametersInternal) {
	log.Trace("Adding scopes 'openid', 'offline_access', 'profile'")
	requestedScopes := authParameters.Scopes
	// openid required to get an id token
	// offline_access required to get a refresh token
	// profile required to get the client_info field back
	requestedScopes = append(requestedScopes, "openid", "offline_access", "profile")
	queryParams["scope"] = msalbase.ConcatenateScopes(requestedScopes)
}

func addClientInfoQueryParam(queryParams map[string]string) {
	queryParams["client_info"] = "1"
}

// addRedirectUriQueryParam stuff
func addRedirectURIQueryParam(queryParams map[string]string, authParameters *msalbase.AuthParametersInternal) {
	queryParams["redirect_uri"] = authParameters.Redirecturi
}

func addContentTypeHeader(headers map[string]string, contentType ContentType) {
	contentTypeKey := "Content-Type"
	switch contentType {
	case SoapXMLUtf8:
		headers[contentTypeKey] = "application/soap+xml; charset=utf-8"
		return

	case URLEncodedUtf8:
		headers[contentTypeKey] = "application/x-www-form-urlencoded; charset=utf-8"
		return
	}
}

func getAadHeaders(authParameters *msalbase.AuthParametersInternal) map[string]string {
	headers := make(map[string]string)

	headers["x-client-SKU"] = fmt.Sprintf("MSAL.golang.%s", runtime.GOOS)
	headers["x-client-OS"] = msalbase.GetOSVersion()
	// headers["x-client-Ver"] = todo: client version here;
	headers["client-request-id"] = authParameters.CorrelationID
	headers["return-client-request-id"] = "false"
	return headers
}

func encodeQueryParameters(queryParameters map[string]string) string {
	var buffer bytes.Buffer

	first := true
	for k, v := range queryParameters {
		if !first {
			buffer.WriteString("&")
		}
		first = false
		buffer.WriteString(url.QueryEscape(k))
		buffer.WriteString("=")
		buffer.WriteString(url.QueryEscape(v))
	}
	result := buffer.String()
	log.Trace(result)
	return result
}

func (wrm *WebRequestManager) exchangeGrantForToken(authParameters *msalbase.AuthParametersInternal, queryParams map[string]string) (*msalbase.TokenResponse, error) {
	headers := getAadHeaders(authParameters)
	addContentTypeHeader(headers, URLEncodedUtf8)

	response, err := wrm.httpManager.Post(authParameters.Endpoints.TokenEndpoint, encodeQueryParameters(queryParams), headers)
	if err != nil {
		return nil, err
	}
	return msalbase.CreateTokenResponse(authParameters, response.GetResponseCode(), response.GetResponseData())
}

// GetAccessTokenFromAuthCode stuff
func (wrm *WebRequestManager) GetAccessTokenFromAuthCode(authParameters *msalbase.AuthParametersInternal, authCode string, codeVerifier string) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":    "authorization_code",
		"code":          authCode,
		"code_verifier": codeVerifier,
	}

	addRedirectURIQueryParam(decodedQueryParams, authParameters)
	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAccessTokenFromRefreshToken stuff
func (wrm *WebRequestManager) GetAccessTokenFromRefreshToken(authParameters *msalbase.AuthParametersInternal, refreshToken string) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
	}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAccessTokenWithCertificate stuff
func (wrm *WebRequestManager) GetAccessTokenWithCertificate(authParameters *msalbase.AuthParametersInternal, certificate *msalbase.ClientCertificate) (*msalbase.TokenResponse, error) {

	assertion := "GetClientCertForAudience()" // todo: string assertion = GetClientCertificateAssertionForAudience(authParameters, certificate);

	decodedQueryParams := map[string]string{
		"grant_type":            "client_credentials",
		"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion":      assertion,
	}

	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAadinstanceDiscoveryResponse stuff
func (wrm *WebRequestManager) GetAadinstanceDiscoveryResponse(
	authorityInfo *msalbase.AuthorityInfo) (*requests.InstanceDiscoveryResponse, error) {

	queryParams := map[string]string{
		"api-version":            "1.1",
		"authorization_endpoint": fmt.Sprintf("https://%v/%v/oauth2/v2.0/authorize", authorityInfo.Host, authorityInfo.Tenant),
	}

	var discoveryHost string
	if requests.IsInTrustedHostList(authorityInfo.Host) {
		discoveryHost = authorityInfo.Host
	} else {
		discoveryHost = "login.microsoftonline.com"
	}

	instanceDiscoveryEndpoint := fmt.Sprintf("https://%v/common/discovery/instance?%v", discoveryHost, encodeQueryParameters(queryParams))
	httpManagerResponse, err := wrm.httpManager.Get(instanceDiscoveryEndpoint, nil)
	if err != nil {
		return nil, err
	}

	if httpManagerResponse.GetResponseCode() != 200 {
		return nil, errors.New("invalid response code") // todo: need error struct here
	}

	return requests.CreateInstanceDiscoveryResponse(httpManagerResponse.GetResponseData())
}

// GetTenantDiscoveryResponse stuff
func (wrm *WebRequestManager) GetTenantDiscoveryResponse(
	openIDConfigurationEndpoint string) (*requests.TenantDiscoveryResponse, error) {

	httpManagerResponse, err := wrm.httpManager.Get(openIDConfigurationEndpoint, nil)
	if err != nil {
		return nil, err
	}

	return requests.CreateTenantDiscoveryResponse(httpManagerResponse.GetResponseCode(), httpManagerResponse.GetResponseData())
}

func (wrm *WebRequestManager) GetProviderConfigurationInformation(authParameters *msalbase.AuthParametersInternal) (*requests.ProviderConfigurationInformation, error) {

	// TODO: load from web and parse...
	configInfoJson := ""

	configInfo := &requests.ProviderConfigurationInformation{}
	err := json.Unmarshal([]byte(configInfoJson), configInfo)
	if err != nil {
		return nil, err
	}

	if configInfo.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("Server response did not contain 'authorization_endpoint' as a string: '%v'", configInfoJson)
	}

	return configInfo, nil
}

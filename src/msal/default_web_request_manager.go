// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/wstrust"
	log "github.com/sirupsen/logrus"
)

// defaultWebRequestManager handles the HTTP calls and request building in MSAL
type defaultWebRequestManager struct {
	httpManager HTTPManager
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

func createWebRequestManager(httpManager HTTPManager) requests.WebRequestManager {
	m := &defaultWebRequestManager{httpManager}
	return m
}

// GetUserRealm stuff
func (wrm *defaultWebRequestManager) GetUserRealm(authParameters *msalbase.AuthParametersInternal) (*msalbase.UserRealm, error) {
	url := authParameters.Endpoints.GetUserRealmEndpoint(authParameters.Username)
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
func (wrm *defaultWebRequestManager) GetMex(federationMetadataURL string) (*wstrust.WsTrustMexDocument, error) {
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
func (wrm *defaultWebRequestManager) GetWsTrustResponse(
	authParameters *msalbase.AuthParametersInternal,
	cloudAudienceURN string,
	endpoint *wstrust.WsTrustEndpoint) (*wstrust.Response, error) {
	var wsTrustRequestMessage string
	var err error

	switch authParameters.AuthorizationType {
	case msalbase.AuthorizationTypeWindowsIntegratedAuth:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageWIA(cloudAudienceURN)
	case msalbase.AuthorizationTypeUsernamePassword:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageUsernamePassword(
			cloudAudienceURN, authParameters.Username, authParameters.Password)
	default:
		err = errors.New("unknown auth type")
	}

	if err != nil {
		return nil, err
	}

	var soapAction string

	if endpoint.EndpointVersion == wstrust.Trust2005 {
		soapAction = msalbase.SoapActionWSTrust2005
	} else {
		soapAction = msalbase.SoapActionDefault
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
func (wrm *defaultWebRequestManager) GetAccessTokenFromSamlGrant(authParameters *msalbase.AuthParametersInternal, samlGrant *wstrust.SamlTokenInfo) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type": msalbase.PasswordGrant,
		"username":   authParameters.Username,
		"password":   authParameters.Password,
	}

	switch samlGrant.AssertionType {
	case wstrust.SamlV1:
		decodedQueryParams["grant_type"] = msalbase.SAMLV1Grant
		break
	case wstrust.SamlV2:
		decodedQueryParams["grant_type"] = msalbase.SAMLV2Grant
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
func (wrm *defaultWebRequestManager) GetAccessTokenFromUsernamePassword(
	authParameters *msalbase.AuthParametersInternal) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type": msalbase.PasswordGrant,
		"username":   authParameters.Username,
		"password":   authParameters.Password,
	}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetDeviceCodeResult stuff
func (wrm *defaultWebRequestManager) GetDeviceCodeResult(authParameters *msalbase.AuthParametersInternal) (*msalbase.DeviceCodeResult, error) {
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
func (wrm *defaultWebRequestManager) GetAccessTokenFromDeviceCodeResult(authParameters *msalbase.AuthParametersInternal, deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":  msalbase.DeviceCodeGrant,
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
	log.Info("Adding scopes 'openid', 'offline_access', 'profile'")
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
	keys := []string{}
	for k := range queryParameters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	first := true
	for _, k := range keys {
		if !first {
			buffer.WriteString("&")
		}
		first = false
		buffer.WriteString(url.QueryEscape(k))
		buffer.WriteString("=")
		buffer.WriteString(url.QueryEscape(queryParameters[k]))
	}
	result := buffer.String()
	return result
}

func (wrm *defaultWebRequestManager) exchangeGrantForToken(authParameters *msalbase.AuthParametersInternal, queryParams map[string]string) (*msalbase.TokenResponse, error) {
	headers := getAadHeaders(authParameters)
	addContentTypeHeader(headers, URLEncodedUtf8)

	response, err := wrm.httpManager.Post(authParameters.Endpoints.TokenEndpoint, encodeQueryParameters(queryParams), headers)
	if err != nil {
		return nil, err
	}
	return msalbase.CreateTokenResponse(authParameters, response.GetResponseCode(), response.GetResponseData())
}

// GetAccessTokenFromAuthCode stuff
func (wrm *defaultWebRequestManager) GetAccessTokenFromAuthCode(authParameters *msalbase.AuthParametersInternal,
	authCode string,
	codeVerifier string,
	params map[string]string) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":    msalbase.AuthCodeGrant,
		"code":          authCode,
		"code_verifier": codeVerifier,
	}
	for k, v := range params {
		decodedQueryParams[k] = v
	}
	addRedirectURIQueryParam(decodedQueryParams, authParameters)
	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAccessTokenFromRefreshToken stuff
func (wrm *defaultWebRequestManager) GetAccessTokenFromRefreshToken(authParameters *msalbase.AuthParametersInternal, refreshToken string) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":    msalbase.RefreshTokenGrant,
		"refresh_token": refreshToken,
	}

	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)

	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

func (wrm *defaultWebRequestManager) GetAccessTokenWithClientSecret(authParameters *msalbase.AuthParametersInternal, clientSecret string) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":    msalbase.ClientCredentialGrant,
		"client_secret": clientSecret,
	}
	addClientIDQueryParam(decodedQueryParams, authParameters)
	addScopeQueryParam(decodedQueryParams, authParameters)
	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAccessTokenWithCertificate stuff
func (wrm *defaultWebRequestManager) GetAccessTokenWithAssertion(authParameters *msalbase.AuthParametersInternal, assertion string) (*msalbase.TokenResponse, error) {
	decodedQueryParams := map[string]string{
		"grant_type":            msalbase.ClientCredentialGrant,
		"client_assertion_type": msalbase.ClientAssertionGrant,
		"client_assertion":      assertion,
	}

	addScopeQueryParam(decodedQueryParams, authParameters)
	addClientInfoQueryParam(decodedQueryParams)
	return wrm.exchangeGrantForToken(authParameters, decodedQueryParams)
}

// GetAadinstanceDiscoveryResponse stuff
func (wrm *defaultWebRequestManager) GetAadinstanceDiscoveryResponse(
	authorityInfo *msalbase.AuthorityInfo) (*requests.InstanceDiscoveryResponse, error) {

	queryParams := map[string]string{
		"api-version":            "1.1",
		"authorization_endpoint": fmt.Sprintf(msalbase.AuthorizationEndpoint, authorityInfo.Host, authorityInfo.Tenant),
	}

	var discoveryHost string
	if requests.IsInTrustedHostList(authorityInfo.Host) {
		discoveryHost = authorityInfo.Host
	} else {
		discoveryHost = msalbase.DefaultHost
	}

	instanceDiscoveryEndpoint := fmt.Sprintf(msalbase.InstanceDiscoveryEndpoint, discoveryHost, encodeQueryParameters(queryParams))
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
func (wrm *defaultWebRequestManager) GetTenantDiscoveryResponse(
	openIDConfigurationEndpoint string) (*requests.TenantDiscoveryResponse, error) {

	httpManagerResponse, err := wrm.httpManager.Get(openIDConfigurationEndpoint, nil)
	if err != nil {
		return nil, err
	}

	return requests.CreateTenantDiscoveryResponse(httpManagerResponse.GetResponseCode(), httpManagerResponse.GetResponseData())
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// TokenRequester is an interface that handles all token acquisition requests
type TokenRequester interface {
	Execute(context.Context) (msalbase.TokenResponse, error)
}

// TODO(jdoak): Remove this.
var instanceDiscoveryCache = map[string]InstanceDiscoveryMetadata{}

type InstanceDiscoveryMetadata struct {
	PreferredNetwork        string   `json:"preferred_network"`
	PreferredCache          string   `json:"preferred_cache"`
	TenantDiscoveryEndpoint string   `json:"tenant_discovery_endpoint"`
	Aliases                 []string `json:"aliases"`

	AdditionalFields map[string]interface{}
}

func createInstanceDiscoveryMetadata(preferredNetwork string, preferredCache string) InstanceDiscoveryMetadata {
	return InstanceDiscoveryMetadata{
		PreferredNetwork: preferredNetwork,
		PreferredCache:   preferredCache,
		Aliases:          []string{},
	}
}

type AadInstanceDiscovery struct {
	webRequestManager WebRequestManager
}

func CreateAadInstanceDiscovery(webRequestManager WebRequestManager) *AadInstanceDiscovery {
	return &AadInstanceDiscovery{webRequestManager: webRequestManager}
}

func (d *AadInstanceDiscovery) doInstanceDiscoveryAndCache(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryMetadata, error) {
	discoveryResponse, err := d.webRequestManager.GetAadinstanceDiscoveryResponse(ctx, authorityInfo)
	if err != nil {
		return InstanceDiscoveryMetadata{}, err
	}

	for _, metadataEntry := range discoveryResponse.Metadata {
		metadataEntry.TenantDiscoveryEndpoint = discoveryResponse.TenantDiscoveryEndpoint
		for _, aliasedAuthority := range metadataEntry.Aliases {
			instanceDiscoveryCache[aliasedAuthority] = metadataEntry
		}
	}
	if _, ok := instanceDiscoveryCache[authorityInfo.Host]; !ok {
		instanceDiscoveryCache[authorityInfo.Host] = createInstanceDiscoveryMetadata(authorityInfo.Host, authorityInfo.Host)
	}
	return instanceDiscoveryCache[authorityInfo.Host], nil
}

func (d *AadInstanceDiscovery) GetMetadataEntry(ctx context.Context, authorityInfo msalbase.AuthorityInfo) (InstanceDiscoveryMetadata, error) {
	if metadata, ok := instanceDiscoveryCache[authorityInfo.Host]; ok {
		return metadata, nil
	}
	metadata, err := d.doInstanceDiscoveryAndCache(ctx, authorityInfo)
	if err != nil {
		return InstanceDiscoveryMetadata{}, err
	}
	return metadata, nil
}

//AuthCodeRequestType is whether the authorization code flow is for a public or confidential client
type AuthCodeRequestType int

//These are the different values for AuthCodeRequestType
const (
	AuthCodePublic AuthCodeRequestType = iota
	AuthCodeConfidential
)

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
	Code              string
	CodeChallenge     string
	ClientCredential  msalbase.ClientCredential
	RequestType       AuthCodeRequestType
}

// CreateAuthCodeRequest creates an instance of AuthCodeRequest
func CreateAuthCodeRequest(webRequestManager WebRequestManager, authParameters msalbase.AuthParametersInternal, reqType AuthCodeRequestType) *AuthCodeRequest {
	return &AuthCodeRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		RequestType:       reqType,
	}
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *AuthCodeRequest) Execute(ctx context.Context) (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, fmt.Errorf("unable to resolve endpoints: %w", err)
	}

	req.authParameters.Endpoints = endpoints
	params := url.Values{}
	if req.RequestType == AuthCodeConfidential {
		if req.ClientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
			params.Set("client_secret", req.ClientCredential.GetSecret())
		} else {
			jwt, err := req.ClientCredential.GetAssertion().GetJWT(req.authParameters)
			if err != nil {
				return msalbase.TokenResponse{}, fmt.Errorf("unable to retrieve JWT from client credentials: %w", err)
			}
			params.Set("client_assertion", jwt)
			params.Set("client_assertion_type", msalbase.ClientAssertionGrant)
		}
	}
	tokenResponse, err := req.webRequestManager.GetAccessTokenFromAuthCode(ctx, req.authParameters, req.Code, req.CodeChallenge, params)
	if err != nil {
		return msalbase.TokenResponse{}, fmt.Errorf("could not retrieve token from auth code: %w", err)
	}
	return tokenResponse, nil
}

type authorityEndpointCacheEntry struct {
	Endpoints             msalbase.AuthorityEndpoints
	ValidForDomainsInList map[string]bool
}

func createAuthorityEndpointCacheEntry(endpoints msalbase.AuthorityEndpoints) authorityEndpointCacheEntry {
	return authorityEndpointCacheEntry{endpoints, map[string]bool{}}
}

var endpointCacheEntries = map[string]authorityEndpointCacheEntry{}

//AuthorityEndpointResolutionManager handles getting the correct endpoints from the authority for auth and token acquisition
type AuthorityEndpointResolutionManager struct {
	webRequestManager WebRequestManager
}

//CreateAuthorityEndpointResolutionManager creates a AuthorityEndpointResolutionManager instance
func CreateAuthorityEndpointResolutionManager(webRequestManager WebRequestManager) *AuthorityEndpointResolutionManager {
	m := &AuthorityEndpointResolutionManager{webRequestManager}
	return m
}

func getAdfsDomainFromUpn(userPrincipalName string) (string, error) {
	parts := strings.Split(userPrincipalName, "@")
	if len(parts) < 2 {
		return "", errors.New("no @ present in user principal name")
	}
	return parts[1], nil
}

func (m *AuthorityEndpointResolutionManager) tryGetCachedEndpoints(authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (msalbase.AuthorityEndpoints, error) {
	if cacheEntry, ok := endpointCacheEntries[authorityInfo.CanonicalAuthorityURI]; ok {
		if authorityInfo.AuthorityType == msalbase.ADFS {
			domain, err := getAdfsDomainFromUpn(userPrincipalName)
			if err == nil {
				if _, ok := cacheEntry.ValidForDomainsInList[domain]; ok {
					return cacheEntry.Endpoints, nil
				}
			}
		}
		return cacheEntry.Endpoints, nil
	}
	return msalbase.AuthorityEndpoints{}, errors.New("endpoint not found")
}

func (m *AuthorityEndpointResolutionManager) addCachedEndpoints(authorityInfo msalbase.AuthorityInfo, userPrincipalName string, endpoints msalbase.AuthorityEndpoints) {
	updatedCacheEntry := createAuthorityEndpointCacheEntry(endpoints)

	if authorityInfo.AuthorityType == msalbase.ADFS {
		// Since we're here, we've made a call to the backend.  We want to ensure we're caching
		// the latest values from the server.
		if cacheEntry, ok := endpointCacheEntries[authorityInfo.CanonicalAuthorityURI]; ok {
			for k := range cacheEntry.ValidForDomainsInList {
				updatedCacheEntry.ValidForDomainsInList[k] = true
			}
		}
		domain, err := getAdfsDomainFromUpn(userPrincipalName)
		if err == nil {
			updatedCacheEntry.ValidForDomainsInList[domain] = true
		}
	}

	endpointCacheEntries[authorityInfo.CanonicalAuthorityURI] = updatedCacheEntry
}

//ResolveEndpoints gets the authorization and token endpoints and creates an AuthorityEndpoints instance
func (m *AuthorityEndpointResolutionManager) ResolveEndpoints(ctx context.Context, authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (msalbase.AuthorityEndpoints, error) {
	if authorityInfo.AuthorityType == msalbase.ADFS && len(userPrincipalName) == 0 {
		return msalbase.AuthorityEndpoints{}, errors.New("UPN required for authority validation for ADFS")
	}

	if endpoints, ok := m.cachedValue(authorityInfo, userPrincipalName); ok {
		return endpoints, nil
	}

	endpointManager, err := createOpenIDConfigurationEndpointManager(authorityInfo)
	if err != nil {
		return msalbase.AuthorityEndpoints{}, err
	}

	openIDConfigurationEndpoint, err := endpointManager.getOpenIDConfigurationEndpoint(ctx, authorityInfo, userPrincipalName)
	if err != nil {
		return msalbase.AuthorityEndpoints{}, err
	}

	// Discover endpoints via openid-configuration
	tenantDiscoveryResponse, err := m.webRequestManager.GetTenantDiscoveryResponse(ctx, openIDConfigurationEndpoint)
	if err != nil {
		return msalbase.AuthorityEndpoints{}, err
	}

	if !tenantDiscoveryResponse.hasAuthorizationEndpoint() {
		return msalbase.AuthorityEndpoints{}, errors.New("authorize endpoint was not found in the openid configuration")
	}
	if !tenantDiscoveryResponse.hasTokenEndpoint() {
		return msalbase.AuthorityEndpoints{}, errors.New("token endpoint was not found in the openid configuration")
	}
	if !tenantDiscoveryResponse.hasIssuer() {
		return msalbase.AuthorityEndpoints{}, errors.New("issuer was not found in the openid configuration")
	}

	tenant := authorityInfo.Tenant

	endpoints := msalbase.CreateAuthorityEndpoints(
		strings.Replace(tenantDiscoveryResponse.AuthorizationEndpoint, "{tenant}", tenant, -1),
		strings.Replace(tenantDiscoveryResponse.TokenEndpoint, "{tenant}", tenant, -1),
		strings.Replace(tenantDiscoveryResponse.Issuer, "{tenant}", tenant, -1),
		authorityInfo.Host)

	m.addCachedEndpoints(authorityInfo, userPrincipalName, endpoints)

	return endpoints, nil
}

func (m *AuthorityEndpointResolutionManager) cachedValue(authorityInfo msalbase.AuthorityInfo, userPrincipalName string) (endpoints msalbase.AuthorityEndpoints, ok bool) {
	endpoints, err := m.tryGetCachedEndpoints(authorityInfo, userPrincipalName)
	if err != nil {
		return endpoints, false
	}
	return endpoints, true
}

//ClientCredentialRequest stores the values required to acquire a token from the authority using a client credentials grant
type ClientCredentialRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
	clientCredential  msalbase.ClientCredential
}

//CreateClientCredentialRequest creates an instance of ClientCredentialRequest
func CreateClientCredentialRequest(wrm WebRequestManager, authParams msalbase.AuthParametersInternal, clientCred msalbase.ClientCredential) *ClientCredentialRequest {
	return &ClientCredentialRequest{wrm, authParams, clientCred}
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *ClientCredentialRequest) Execute(ctx context.Context) (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	req.authParameters.Endpoints = endpoints

	if req.clientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
		return req.webRequestManager.GetAccessTokenWithClientSecret(ctx, req.authParameters, req.clientCredential.GetSecret())
	}
	jwt, err := req.clientCredential.GetAssertion().GetJWT(req.authParameters)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	return req.webRequestManager.GetAccessTokenWithAssertion(ctx, req.authParameters, jwt)
}

// DeviceCodeResponse represents the HTTP response received from the device code endpoint
type DeviceCodeResponse struct {
	msalbase.OAuthResponseBase

	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`

	AdditionalFields map[string]interface{}
}

// CreateDeviceCodeResponse creates a deviceCodeResponse instance from HTTP response.
func CreateDeviceCodeResponse(resp *http.Response) (DeviceCodeResponse, error) {
	dcResponse := DeviceCodeResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return dcResponse, err
	}

	if err := json.Unmarshal(body, &dcResponse); err != nil {
		return dcResponse, err
	}

	if dcResponse.Error != "" {
		return dcResponse, fmt.Errorf("%s: %s", dcResponse.Error, dcResponse.ErrorDescription)
	}
	return dcResponse, nil
}

//ToDeviceCodeResult converts the DeviceCodeResponse to a DeviceCodeResult
func (dcr DeviceCodeResponse) ToDeviceCodeResult(clientID string, scopes []string) msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.CreateDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// InstanceDiscoveryResponse stuff
type InstanceDiscoveryResponse struct {
	TenantDiscoveryEndpoint string                      `json:"tenant_discovery_endpoint"`
	Metadata                []InstanceDiscoveryMetadata `json:"metadata"`

	AdditionalFields map[string]interface{}
}

func CreateInstanceDiscoveryResponse(resp *http.Response) (InstanceDiscoveryResponse, error) {
	idr := InstanceDiscoveryResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return idr, err
	}
	return idr, json.Unmarshal(body, &idr)
}

// TenantDiscoveryResponse consists of the tenant endpoints from the OpenID configuration endpoint
type TenantDiscoveryResponse struct {
	msalbase.OAuthResponseBase

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`

	AdditionalFields map[string]interface{}
}

func (r *TenantDiscoveryResponse) hasAuthorizationEndpoint() bool {
	return len(r.AuthorizationEndpoint) > 0
}

func (r *TenantDiscoveryResponse) hasTokenEndpoint() bool {
	return len(r.TokenEndpoint) > 0
}

func (r *TenantDiscoveryResponse) hasIssuer() bool {
	return len(r.Issuer) > 0
}

//CreateTenantDiscoveryResponse creates a tenant discovery response instance from an HTTP response
func CreateTenantDiscoveryResponse(resp *http.Response) (TenantDiscoveryResponse, error) {
	tdr := TenantDiscoveryResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return tdr, err
	}

	err = json.Unmarshal(body, &tdr)
	if err != nil {
		return tdr, err
	}

	if tdr.Error != "" {
		return TenantDiscoveryResponse{}, fmt.Errorf("%s: %s", tdr.Error, tdr.ErrorDescription)
	}

	return tdr, nil
}

// UsernamePasswordRequest stuff
type UsernamePasswordRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
}

// CreateUsernamePasswordRequest stuff
func CreateUsernamePasswordRequest(webRequestManager WebRequestManager, authParameters msalbase.AuthParametersInternal) *UsernamePasswordRequest {
	req := &UsernamePasswordRequest{webRequestManager, authParameters}
	return req
}

func (req *UsernamePasswordRequest) Execute(ctx context.Context) (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, err
	}

	req.authParameters.Endpoints = endpoints

	userRealm, err := req.webRequestManager.GetUserRealm(ctx, req.authParameters)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}

	switch accountType := userRealm.GetAccountType(); accountType {
	case msalbase.Federated:
		mexDoc, err := req.webRequestManager.GetMex(ctx, userRealm.FederationMetadataURL)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		wsTrustEndpoint := mexDoc.UsernamePasswordEndpoint
		wsTrustResponse, err := req.webRequestManager.GetWsTrustResponse(ctx, req.authParameters, userRealm.CloudAudienceURN, wsTrustEndpoint)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		samlGrant, err := wsTrustResponse.GetSAMLAssertion(wsTrustEndpoint)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		return req.webRequestManager.GetAccessTokenFromSamlGrant(ctx, req.authParameters, samlGrant)
	case msalbase.Managed:
		return req.webRequestManager.GetAccessTokenFromUsernamePassword(ctx, req.authParameters)
	}
	return msalbase.TokenResponse{}, errors.New("unknown account type")
}

//RefreshTokenReqType is whether the refresh token flow is for a public or confidential client
type RefreshTokenReqType int

//These are the different values for RefreshTokenReqType
const (
	RefreshTokenPublic RefreshTokenReqType = iota
	RefreshTokenConfidential
)

// RefreshTokenExchangeRequest stores the values required to request a token from the authority using a refresh token
type RefreshTokenExchangeRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
	refreshToken      msalbase.Credential
	ClientCredential  msalbase.ClientCredential
	RequestType       RefreshTokenReqType
}

// NewRefreshTokenExchangeRequest creates a RefreshTokenExchangeRequest instance
func NewRefreshTokenExchangeRequest(webRequestManager WebRequestManager, authParameters msalbase.AuthParametersInternal, refreshToken msalbase.Credential, reqType RefreshTokenReqType) *RefreshTokenExchangeRequest {
	req := &RefreshTokenExchangeRequest{
		webRequestManager: webRequestManager,
		authParameters:    authParameters,
		refreshToken:      refreshToken,
		RequestType:       reqType,
	}
	return req
}

//Execute performs the token acquisition request and returns a token response or an error
func (req *RefreshTokenExchangeRequest) Execute(ctx context.Context) (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, err
	}
	req.authParameters.Endpoints = endpoints
	params := url.Values{}
	if req.RequestType == RefreshTokenConfidential {
		if req.ClientCredential.GetCredentialType() == msalbase.ClientCredentialSecret {
			params.Set("client_secret", req.ClientCredential.GetSecret())
		} else {
			jwt, err := req.ClientCredential.GetAssertion().GetJWT(req.authParameters)
			if err != nil {
				return msalbase.TokenResponse{}, err
			}
			params.Set("client_assertion", jwt)
			params.Set("client_assertion_type", msalbase.ClientAssertionGrant)
		}
	}
	return req.webRequestManager.GetAccessTokenFromRefreshToken(ctx, req.authParameters, req.refreshToken.GetSecret(), params)
}

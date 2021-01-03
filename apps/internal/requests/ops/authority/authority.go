// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/google/uuid"
)

const (
	authorizationEndpoint     = "https://%v/%v/oauth2/v2.0/authorize"
	instanceDiscoveryEndpoint = "https://%v/common/discovery/instance"
	defaultHost               = "login.microsoftonline.com"
)

type jsonCaller interface {
	JSONCall(ctx context.Context, endpoint string, headers http.Header, qv url.Values, body, resp interface{}) error
}

var aadTrustedHostList = map[string]bool{
	"login.windows.net":            true, // Microsoft Azure Worldwide - Used in validation scenarios where host is not this list
	"login.chinacloudapi.cn":       true, // Microsoft Azure China
	"login.microsoftonline.de":     true, // Microsoft Azure Blackforest
	"login-us.microsoftonline.com": true, // Microsoft Azure US Government - Legacy
	"login.microsoftonline.us":     true, // Microsoft Azure US Government
	"login.microsoftonline.com":    true, // Microsoft Azure Worldwide
	"login.cloudgovapi.us":         true, // Microsoft Azure US Government
}

// TrustedHost checks if an AAD host is trusted/valid.
func TrustedHost(host string) bool {
	if _, ok := aadTrustedHostList[host]; ok {
		return true
	}
	return false
}

type OAuthResponseBase struct {
	Error            string `json:"error"`
	SubError         string `json:"suberror"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	CorrelationID    string `json:"correlation_id"`
	Claims           string `json:"claims"`
}

// TenantDiscoveryResponse is the tenant endpoints from the OpenID configuration endpoint.
type TenantDiscoveryResponse struct {
	OAuthResponseBase

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`

	AdditionalFields map[string]interface{}
}

// Validate validates that the response had the correct values required.
func (r *TenantDiscoveryResponse) Validate() error {
	switch "" {
	case r.AuthorizationEndpoint:
		return errors.New("TenantDiscoveryResponse: authorize endpoint was not found in the openid configuration")
	case r.TokenEndpoint:
		return errors.New("TenantDiscoveryResponse: token endpoint was not found in the openid configuration")
	case r.Issuer:
		return errors.New("TenantDiscoveryResponse: issuer was not found in the openid configuration")
	}
	return nil
}

func (r *TenantDiscoveryResponse) HasauthorizationEndpoint() bool {
	return len(r.AuthorizationEndpoint) > 0
}

func (r *TenantDiscoveryResponse) HasTokenEndpoint() bool {
	return len(r.TokenEndpoint) > 0
}

func (r *TenantDiscoveryResponse) HasIssuer() bool {
	return len(r.Issuer) > 0
}

type InstanceDiscoveryMetadata struct {
	PreferredNetwork        string   `json:"preferred_network"`
	PreferredCache          string   `json:"preferred_cache"`
	TenantDiscoveryEndpoint string   `json:"tenant_discovery_endpoint"`
	Aliases                 []string `json:"aliases"`

	AdditionalFields map[string]interface{}
}

type InstanceDiscoveryResponse struct {
	TenantDiscoveryEndpoint string                      `json:"tenant_discovery_endpoint"`
	Metadata                []InstanceDiscoveryMetadata `json:"metadata"`

	AdditionalFields map[string]interface{}
}

// This is what this should finally look like.
/*
// Endpoints consists of the endpoints from the tenant discovery response.
type Endpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	selfSignedJwtAudience string
	authorityHost         string
}

// NewEndpoints creates an Endpoints object.
func NewEndpoints(authorizationEndpoint string, tokenEndpoint string, selfSignedJwtAudience string, authorityHost string) AuthorityEndpoints {
	return Endpoints{authorizationEndpoint, tokenEndpoint, selfSignedJwtAudience, authorityHost}
}

// GetUserRealmEndpoint returns the endpoint to get the user realm.
func (endpoints Endpoints) GetUserRealmEndpoint(username string) string {
	return fmt.Sprintf("https://%s/common/UserRealm/%s?api-version=1.0", endpoints.authorityHost, url.PathEscape(username))
}

// Info consists of information about the authority.
type Info struct {
	Host                  string
	CanonicalAuthorityURI string
	AuthorityType         string
	UserRealmURIPrefix    string
	ValidateAuthority     bool
	Tenant                string
}

func canonicalizeAuthorityURI(input string) string {
	val := input
	// todo: ensure ends with /
	return strings.ToLower(val)
}

func validateAuthorityURI(input string) error {
	return nil
}

func getFirstPathSegment(u *url.URL) (string, error) {
	pathParts := strings.Split(u.EscapedPath(), "/")
	if len(pathParts) >= 2 {
		return pathParts[1], nil
	}

	return "", errors.New("authority does not have two segments")
}

func newInfo(authorityType string, authorityURI string, validateAuthority bool) (Info, error) {
	u, err := url.Parse(authorityURI)
	if err != nil {
		return Info{}, err
	}

	host := u.Hostname()
	userRealmURIPrefix := fmt.Sprintf("https://%v/common/userrealm/", host)
	tenant, err := getFirstPathSegment(u)
	if err != nil {
		return Info{}, err
	}

	canonicalAuthorityURI := fmt.Sprintf("https://%v/%v/", host, tenant)

	return Info{host, canonicalAuthorityURI, authorityType, userRealmURIPrefix, validateAuthority, tenant}, nil
}

// NewInfoFromURI creates an Info instance from the authority URL provided.
func NewInfoFromURI(authorityURI string, validateAuthority bool) (Info, error) {
	canonicalURI := canonicalizeAuthorityURI(authorityURI)
	err := validateAuthorityURI(canonicalURI)
	if err != nil {
		return Info{}, err
	}

	// TODO(msal): check for other authority types...
	//ADFS  = "ADFS"
	// B2C   = "B2C"

	return newInfo("MSST", canonicalURI, validateAuthority)
}

//go:generate stringer -type=AuthorizationType

// AuthorizationType represents the type of token flow.
type AuthorizationType int

// These are all the types of token flows.
// TODO(jdoak): Rename all of these and replace AuthorizationTypeNone with Unknown*.
const (
	ATUnknown               AuthorizationType = iota
	ATUsernamePassword                        = iota
	ATWindowsIntegratedAuth                   = iota
	ATAuthCode                                = iota
	ATInteractive                             = iota
	ATClientCredentials                       = iota
	ATDeviceCode                              = iota
	ATRefreshTokenExchange                    = iota
)

// AuthParams represents the parameters used for authorization for token acquisition.
type AuthParams struct {
	Info              Info
	CorrelationID     string
	Endpoints         Endpoints
	ClientID          string
	Redirecturi       string
	HomeaccountID     string
	Username          string
	Password          string
	Scopes            []string
	AuthorizationType AuthorizationType
}

// NewAuthParams is the constructor for AuthParams.
func NewAuthParams(clientID string, info Info) AuthParameters {
	return AuthParameters{
		ClientID:      clientID,
		Info:          info,
		CorrelationID: uuid.New().String(),
	}
}
*/

//go:generate stringer -type=AuthorizationType

// AuthorizationType represents the type of token flow.
type AuthorizationType int

// These are all the types of token flows.
// TODO(jdoak): Rename all of these and replace AuthorizationTypeNone with Unknown*.
const (
	AuthorizationTypeUnknown               AuthorizationType = iota
	AuthorizationTypeUsernamePassword                        = iota
	AuthorizationTypeWindowsIntegratedAuth                   = iota
	AuthorizationTypeAuthCode                                = iota
	AuthorizationTypeInteractive                             = iota
	AuthorizationTypeClientCredentials                       = iota
	AuthorizationTypeDeviceCode                              = iota
	AuthorizationTypeRefreshTokenExchange                    = iota
)

// AuthParams represents the parameters used for authorization for token acquisition.
type AuthParams struct {
	AuthorityInfo     Info
	CorrelationID     string
	Endpoints         AuthorityEndpoints
	ClientID          string
	Redirecturi       string
	HomeaccountID     string
	Username          string
	Password          string
	Scopes            []string
	AuthorizationType AuthorizationType
}

// NewAuthParams creates an authorization parameters object.
func NewAuthParams(clientID string, authorityInfo Info) AuthParams {
	return AuthParams{
		ClientID:      clientID,
		AuthorityInfo: authorityInfo,
		CorrelationID: uuid.New().String(),
	}
}

// Info consists of information about the authority.
type Info struct {
	Host                  string
	CanonicalAuthorityURI string
	AuthorityType         string
	UserRealmURIPrefix    string
	ValidateAuthority     bool
	Tenant                string
}

func canonicalizeAuthorityURI(input string) string {
	val := input
	// todo: ensure ends with /
	return strings.ToLower(val)
}

func validateAuthorityURI(input string) error {
	return nil
}

func getFirstPathSegment(u *url.URL) (string, error) {
	pathParts := strings.Split(u.EscapedPath(), "/")
	if len(pathParts) >= 2 {
		return pathParts[1], nil
	}

	return "", errors.New("authority does not have two segments")
}

func createAuthorityInfo(authorityType string, authorityURI string, validateAuthority bool) (Info, error) {
	u, err := url.Parse(authorityURI)
	if err != nil {
		return Info{}, err
	}

	host := u.Hostname()
	userRealmURIPrefix := fmt.Sprintf("https://%v/common/userrealm/", host)
	tenant, err := getFirstPathSegment(u)
	if err != nil {
		return Info{}, err
	}

	canonicalAuthorityURI := fmt.Sprintf("https://%v/%v/", host, tenant)

	return Info{host, canonicalAuthorityURI, authorityType, userRealmURIPrefix, validateAuthority, tenant}, nil
}

// CreateAuthorityInfoFromAuthorityURI creates an AuthorityInfo instance from the authority URL provided.
func CreateAuthorityInfoFromAuthorityURI(authorityURI string, validateAuthority bool) (Info, error) {
	canonicalURI := canonicalizeAuthorityURI(authorityURI)
	err := validateAuthorityURI(canonicalURI)
	if err != nil {
		return Info{}, err
	}

	// todo: check for other authority types...
	authorityType := "MSSTS"

	return createAuthorityInfo(authorityType, canonicalURI, validateAuthority)
}

// AuthorityEndpoints consists of the endpoints from the tenant discovery response.
type AuthorityEndpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	selfSignedJwtAudience string
	authorityHost         string
}

// CreateAuthorityEndpoints creates an AuthorityEndpoints object.
func CreateAuthorityEndpoints(authorizationEndpoint string, tokenEndpoint string, selfSignedJwtAudience string, authorityHost string) AuthorityEndpoints {
	return AuthorityEndpoints{authorizationEndpoint, tokenEndpoint, selfSignedJwtAudience, authorityHost}
}

// GetUserRealmEndpoint returns the endpoint to get the user realm.
func (endpoints AuthorityEndpoints) GetUserRealmEndpoint(username string) string {
	return fmt.Sprintf("https://%s/common/UserRealm/%s?api-version=1.0", endpoints.authorityHost, url.PathEscape(username))
}

// Client represents the REST calls to authority backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm jsonCaller // *comm.Client
}

func (c Client) GetUserRealm(ctx context.Context, authParameters AuthParams) (msalbase.UserRealm, error) {
	endpoint := authParameters.Endpoints.GetUserRealmEndpoint(authParameters.Username)

	resp := msalbase.UserRealm{}
	err := c.Comm.JSONCall(
		ctx,
		endpoint,
		// TODO(jdoak): not thrilled about this, because all calls should have this but
		// only calls with authParameters is using this.
		http.Header{"client-request-id": []string{authParameters.CorrelationID}},
		nil,
		nil,
		&resp,
	)
	return resp, err
}

func (c Client) GetTenantDiscoveryResponse(ctx context.Context, openIDConfigurationEndpoint string) (TenantDiscoveryResponse, error) {
	resp := TenantDiscoveryResponse{}
	err := c.Comm.JSONCall(
		ctx,
		openIDConfigurationEndpoint,
		http.Header{},
		nil,
		nil,
		&resp,
	)

	return resp, err
}

func (c Client) GetAadinstanceDiscoveryResponse(ctx context.Context, authorityInfo Info) (InstanceDiscoveryResponse, error) {
	qv := url.Values{}
	qv.Set("api-version", "1.1")
	qv.Set("authorization_endpoint", fmt.Sprintf(authorizationEndpoint, authorityInfo.Host, authorityInfo.Tenant))

	discoveryHost := defaultHost
	if TrustedHost(authorityInfo.Host) {
		discoveryHost = authorityInfo.Host
	}

	endpoint := fmt.Sprintf(instanceDiscoveryEndpoint, discoveryHost)

	resp := InstanceDiscoveryResponse{}
	err := c.Comm.JSONCall(ctx, endpoint, http.Header{}, qv, nil, &resp)
	return resp, err
}

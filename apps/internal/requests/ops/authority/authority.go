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
	Endpoints         Endpoints
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

func getFirstPathSegment(u *url.URL) (string, error) {
	pathParts := strings.Split(u.EscapedPath(), "/")
	if len(pathParts) >= 2 {
		return pathParts[1], nil
	}

	return "", errors.New("authority does not have two segments")
}

// NewInfoFromAuthorityURI creates an AuthorityInfo instance from the authority URL provided.
func NewInfoFromAuthorityURI(authorityURI string, validateAuthority bool) (Info, error) {
	authorityURI = strings.ToLower(authorityURI)

	// TODO(msal): The original code I found had a validateAuthority() function.
	// But the function just returned error == nil. I took this from the python and
	// it looks like this needs a lot more. Right now we just pretend its validated.
	/*
			if (tenant != "adfs" and (not is_b2c) and validate_authority
		                and self.instance not in WELL_KNOWN_AUTHORITY_HOSTS):
		            payload = instance_discovery(
		                "https://{}{}/oauth2/v2.0/authorize".format(
		                    self.instance, authority.path),
		                self.http_client)
		            if payload.get("error") == "invalid_instance":
		                raise ValueError(
		                    "invalid_instance: "
		                    "The authority you provided, %s, is not whitelisted. "
		                    "If it is indeed your legit customized domain name, "
		                    "you can turn off this check by passing in "
		                    "validate_authority=False"
		                    % authority_url)
		            tenant_discovery_endpoint = payload['tenant_discovery_endpoint']
		        else:
		            tenant_discovery_endpoint = (
		                'https://{}{}{}/.well-known/openid-configuration'.format(
		                    self.instance,
		                    authority.path,  # In B2C scenario, it is "/tenant/policy"
		                    "" if tenant == "adfs" else "/v2.0" # the AAD v2 endpoint
		                    ))
		        try:
		            openid_config = tenant_discovery(
		                tenant_discovery_endpoint,
		                self.http_client)
		        except ValueError:
		            raise ValueError(
		                "Unable to get authority configuration for {}. "
		                "Authority would typically be in a format of "
		                "https://login.microsoftonline.com/your_tenant_name".format(
						authority_url))
	*/

	// todo: check for other authority types...
	authorityType := "MSSTS"

	u, err := url.Parse(authorityURI)
	if err != nil {
		return Info{}, fmt.Errorf("authorityURI passed could not be parsed: %w", err)
	}
	if u.Scheme != "https" {
		return Info{}, fmt.Errorf("authorityURI(%s) must have scheme https", authorityURI)
	}

	tenant, err := getFirstPathSegment(u)
	if err != nil {
		return Info{}, err
	}

	return Info{
		Host:                  u.Hostname(),
		CanonicalAuthorityURI: fmt.Sprintf("https://%v/%v/", u.Hostname(), tenant),
		AuthorityType:         authorityType,
		UserRealmURIPrefix:    fmt.Sprintf("https://%v/common/userrealm/", u.Hostname()),
		ValidateAuthority:     validateAuthority,
		Tenant:                tenant,
	}, nil
}

// Endpoints consists of the endpoints from the tenant discovery response.
type Endpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	selfSignedJwtAudience string
	authorityHost         string
}

// NewEndpoints creates an Endpoints object.
func NewEndpoints(authorizationEndpoint string, tokenEndpoint string, selfSignedJwtAudience string, authorityHost string) Endpoints {
	return Endpoints{authorizationEndpoint, tokenEndpoint, selfSignedJwtAudience, authorityHost}
}

// UserRealmEndpoint returns the endpoint to get the user realm.
func (e Endpoints) UserRealmEndpoint(username string) string {
	return fmt.Sprintf("https://%s/common/UserRealm/%s?api-version=1.0", e.authorityHost, url.PathEscape(username))
}

//go:generate stringer -type=UserRealmAccountType

// UserRealmAccountType refers to the type of user realm.
type UserRealmAccountType string

// These are the different types of user realms.
const (
	Unknown   UserRealmAccountType = ""
	Federated                      = "Federated"
	Managed                        = "Managed"
)

//UserRealm is used for the username password request to determine user type
type UserRealm struct {
	AccountType       UserRealmAccountType `json:"account_type"`
	DomainName        string               `json:"domain_name"`
	CloudInstanceName string               `json:"cloud_instance_name"`
	CloudAudienceURN  string               `json:"cloud_audience_urn"`

	// required if accountType is Federated
	FederationProtocol    string `json:"federation_protocol"`
	FederationMetadataURL string `json:"federation_metadata_url"`

	AdditionalFields map[string]interface{}
}

func (u UserRealm) validate() error {
	switch "" {
	case string(u.AccountType):
		return errors.New("the account type (Federated or Managed) is missing")
	case u.DomainName:
		return errors.New("domain name of user realm is missing")
	case u.CloudInstanceName:
		return errors.New("cloud instance name of user realm is missing")
	case u.CloudAudienceURN:
		return errors.New("cloud Instance URN is missing")
	}

	if u.AccountType == Federated {
		switch "" {
		case u.FederationProtocol:
			return errors.New("federation protocol of user realm is missing")
		case u.FederationMetadataURL:
			return errors.New("federation metadata URL of user realm is missing")
		}
	}
	return nil
}

// Client represents the REST calls to authority backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm jsonCaller // *comm.Client
}

func (c Client) GetUserRealm(ctx context.Context, authParams AuthParams) (UserRealm, error) {
	endpoint := authParams.Endpoints.UserRealmEndpoint(authParams.Username)

	// 400 AADSTS90014: The required field 'api-version' is missing from the credential. Ensure that you have all the necessary parameters for the login request."
	resp := UserRealm{}
	err := c.Comm.JSONCall(
		ctx,
		endpoint,
		// TODO(jdoak): not thrilled about this, because all calls should have this but
		// only calls with authParameters is using this.
		http.Header{
			"client-request-id": []string{authParams.CorrelationID},
		},
		url.Values{
			"api-version": []string{"1.1"},
		},
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

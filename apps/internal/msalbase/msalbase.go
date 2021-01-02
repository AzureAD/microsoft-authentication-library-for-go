// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"
	jwt "github.com/dgrijalva/jwt-go"
	uuid "github.com/google/uuid"
)

const (
	scopeSeparator = " "

	// CacheKeySeparator is used in creating the keys of the cache.
	CacheKeySeparator = "-"

	// Credential Types.

	CredentialTypeRefreshToken = "RefreshToken"
	CredentialTypeAccessToken  = "AccessToken"
	CredentialTypeIDToken      = "IDToken"

	// Authority Types.

	MSSTS = "MSSTS"
	ADFS  = "ADFS"
	B2C   = "B2C"

	// Grant Types.

	PasswordGrant         = "password"
	SAMLV1Grant           = "urn:ietf:params:oauth:grant-type:saml1_1-bearer"
	SAMLV2Grant           = "urn:ietf:params:oauth:grant-type:saml2-bearer"
	DeviceCodeGrant       = "device_code"
	AuthCodeGrant         = "authorization_code"
	RefreshTokenGrant     = "refresh_token"
	ClientCredentialGrant = "client_credentials"
	ClientAssertionGrant  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	// Endpoints.

	AuthorizationEndpoint     = "https://%v/%v/oauth2/v2.0/authorize"
	InstanceDiscoveryEndpoint = "https://%v/common/discovery/instance"
	DefaultHost               = "login.microsoftonline.com"
)

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

// TODO(jdoak): This needs to move out of here.  Both apps/public and apps/confidential return
// this. Or at the least, we need to type alias this up there.

type Account struct {
	HomeAccountID     string `json:"home_account_id,omitempty"`
	Environment       string `json:"environment,omitempty"`
	Realm             string `json:"realm,omitempty"`
	LocalAccountID    string `json:"local_account_id,omitempty"`
	AuthorityType     string `json:"authority_type,omitempty"`
	PreferredUsername string `json:"username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Name              string `json:"name,omitempty"`
	AlternativeID     string `json:"alternative_account_id,omitempty"`
	RawClientInfo     string `json:"client_info,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewAccount creates an account.
func NewAccount(homeAccountID, env, realm, localAccountID, authorityType, username string) Account {
	return Account{
		HomeAccountID:     homeAccountID,
		Environment:       env,
		Realm:             realm,
		LocalAccountID:    localAccountID,
		AuthorityType:     authorityType,
		PreferredUsername: username,
	}
}

// Key creates the key for storing accounts in the cache.
func (acc Account) Key() string {
	return strings.Join([]string{acc.HomeAccountID, acc.Environment, acc.Realm}, CacheKeySeparator)
}

// GetUsername returns the username of an account.
func (acc Account) GetUsername() string {
	return acc.PreferredUsername
}

// GetHomeAccountID returns the home account ID of an account.
func (acc Account) GetHomeAccountID() string {
	return acc.HomeAccountID
}

// GetEnvironment returns the environment of an account.
func (acc Account) GetEnvironment() string {
	return acc.Environment
}

//go:generate stringer -type=AuthorizationType

// AuthorizationType represents the type of token flow.
type AuthorizationType int

//go:generate stringer -type=AuthorizationType
// These are all the types of token flows.
// TODO(jdoak): Rename all of these and replace AuthorizationTypeNone with Unknown*.
const (
	AuthorizationTypeNone                  AuthorizationType = iota
	AuthorizationTypeUsernamePassword                        = iota
	AuthorizationTypeWindowsIntegratedAuth                   = iota
	AuthorizationTypeAuthCode                                = iota
	AuthorizationTypeInteractive                             = iota
	AuthorizationTypeClientCredentials                       = iota
	AuthorizationTypeDeviceCode                              = iota
	AuthorizationTypeRefreshTokenExchange                    = iota
)

// AuthParametersInternal represents the parameters used for authorization for token acquisition.
type AuthParametersInternal struct {
	AuthorityInfo     AuthorityInfo
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

// CreateAuthParametersInternal creates an authorization parameters object.
func CreateAuthParametersInternal(clientID string, authorityInfo AuthorityInfo) AuthParametersInternal {
	return AuthParametersInternal{
		ClientID:      clientID,
		AuthorityInfo: authorityInfo,
		CorrelationID: uuid.New().String(),
	}
}

// AuthorityInfo consists of information about the authority.
type AuthorityInfo struct {
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

func createAuthorityInfo(authorityType string, authorityURI string, validateAuthority bool) (AuthorityInfo, error) {
	u, err := url.Parse(authorityURI)
	if err != nil {
		return AuthorityInfo{}, err
	}

	host := u.Hostname()
	userRealmURIPrefix := fmt.Sprintf("https://%v/common/userrealm/", host)
	tenant, err := getFirstPathSegment(u)
	if err != nil {
		return AuthorityInfo{}, err
	}

	canonicalAuthorityURI := fmt.Sprintf("https://%v/%v/", host, tenant)

	return AuthorityInfo{host, canonicalAuthorityURI, authorityType, userRealmURIPrefix, validateAuthority, tenant}, nil
}

// CreateAuthorityInfoFromAuthorityURI creates an AuthorityInfo instance from the authority URL provided.
func CreateAuthorityInfoFromAuthorityURI(authorityURI string, validateAuthority bool) (AuthorityInfo, error) {
	canonicalURI := canonicalizeAuthorityURI(authorityURI)
	err := validateAuthorityURI(canonicalURI)
	if err != nil {
		return AuthorityInfo{}, err
	}

	// todo: check for other authority types...
	authorityType := MSSTS

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

// Credential represents the credential used in confidential client flows. This can be either
// a Secret or Cert/Key.
type Credential struct {
	Secret string

	Cert *x509.Certificate
	Key  crypto.PrivateKey

	mu        sync.Mutex
	assertion string
	expires   time.Time
}

// JWT gets the jwt assertion when the credential is not using a secret.
func (c *Credential) JWT(authParams AuthParametersInternal) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.expires.Before(time.Now()) && c.assertion != "" {
		return c.assertion, nil
	}
	expires := time.Now().Add(5 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": authParams.Endpoints.TokenEndpoint,
		"exp": strconv.FormatInt(expires.Unix(), 10),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": strconv.FormatInt(time.Now().Unix(), 10),
		"sub": authParams.ClientID,
	})
	token.Header = map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": base64.StdEncoding.EncodeToString(thumbprint(c.Cert)),
	}

	var err error
	c.assertion, err = token.SignedString(c.Key)
	if err != nil {
		return "", err
	}

	c.expires = expires
	return c.assertion, err
}

// thumbprint runs the asn1.Der bytes through sha1 for use in the x5t parameter of JWT.
// https://tools.ietf.org/html/rfc7517#section-4.8
func thumbprint(cert *x509.Certificate) []byte {
	a := sha1.Sum(cert.Raw)
	return a[:]
}

// DeviceCodeResult stores the response from the STS device code endpoint.
// TODO(jdoak): Make these attributes public, maybe remove .String().
type DeviceCodeResult struct {
	// UserCode is the code the user needs to provide when authentication at the verification URI.
	UserCode string
	// DeviceCode is the code used in the access token request.
	DeviceCode string
	// VerificationURL is the the URL where user can authenticate.
	VerificationURL string
	// ExpiresOn is the expiration time of device code in seconds.
	ExpiresOn time.Time
	// Interval is the interval at which the STS should be polled at.
	Interval int
	// Message is the message which should be displayed to the user.
	Message string
	// ClientID is the UUID issued by the authorization server for your application.
	ClientID string
	// Scopes is the OpenID scopes used to request access a protected API.
	Scopes []string
}

// NewDeviceCodeResult creates a DeviceCodeResult instance.
func NewDeviceCodeResult(userCode, deviceCode, verificationURL string, expiresOn time.Time, interval int, message, clientID string, scopes []string) DeviceCodeResult {
	return DeviceCodeResult{userCode, deviceCode, verificationURL, expiresOn, interval, message, clientID, scopes}
}

func (dcr DeviceCodeResult) String() string {
	return fmt.Sprintf("UserCode: (%v)\nDeviceCode: (%v)\nURL: (%v)\nMessage: (%v)\n", dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, dcr.Message)

}

//go:generate stringer -type=UserRealmAccountType

// UserRealmAccountType refers to the type of user realm.
type UserRealmAccountType int

// These are the different types of user realms.
const (
	Unknown UserRealmAccountType = iota
	Federated
	Managed
)

//UserRealm is used for the username password request to determine user type
type UserRealm struct {
	AccountType       string `json:"account_type"`
	DomainName        string `json:"domain_name"`
	CloudInstanceName string `json:"cloud_instance_name"`
	CloudAudienceURN  string `json:"cloud_audience_urn"`

	// required if accountType is Federated
	FederationProtocol    string `json:"federation_protocol"`
	FederationMetadataURL string `json:"federation_metadata_url"`

	AdditionalFields map[string]interface{}
}

func (u UserRealm) validate() error {
	switch "" {
	case u.DomainName:
		return errors.New("domain name of user realm is missing")
	case u.CloudInstanceName:
		return errors.New("cloud instance name of user realm is missing")
	case u.CloudAudienceURN:
		return errors.New("cloud Instance URN is missing")
	}

	if u.GetAccountType() == Federated {
		switch "" {
		case u.FederationProtocol:
			return errors.New("federation protocol of user realm is missing")
		case u.FederationMetadataURL:
			return errors.New("federation metadata URL of user realm is missing")
		}
	}
	return nil
}

// CreateUserRealm creates a UserRealm instance from the HTTP response
func CreateUserRealm(resp *http.Response) (UserRealm, error) {
	u := UserRealm{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return u, err
	}
	err = json.Unmarshal(body, &u)
	if err != nil {
		return u, err
	}
	return u, u.validate()
}

//GetAccountType gets the type of user account
func (u *UserRealm) GetAccountType() UserRealmAccountType {
	if u.AccountType == "Federated" {
		return Federated
	}
	if u.AccountType == "Managed" {
		return Managed
	}
	return Unknown
}

type OAuthResponseBase struct {
	Error            string `json:"error"`
	SubError         string `json:"suberror"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	CorrelationID    string `json:"correlation_id"`
	Claims           string `json:"claims"`

	AdditionalFields map[string]interface{}
}

type TokenResponseJSONPayload struct {
	OAuthResponseBase

	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	Foci         string `json:"foci"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	// TODO(msal): If this is always going to be a JWT base64 encoded, we should consider
	// making this a json.RawMessage. Then we can do our decodes in []byte and pass it
	// to our json decoder directly instead of all the extra copies from using string.
	// This means changing DecodeJWT().
	ClientInfo string `json:"client_info"`

	AdditionalFields map[string]interface{}
}

// ClientInfoJSONPayload is used to create a Home Account ID for an account.
type ClientInfoJSONPayload struct {
	UID  string `json:"uid"`
	Utid string `json:"utid"`

	AdditionalFields map[string]interface{}
}

// RefreshToken is the JSON representation of a MSAL refresh token for encoding to storage.
type RefreshToken struct {
	HomeAccountID  string `json:"home_account_id,omitempty"`
	Environment    string `json:"environment,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	FamilyID       string `json:"family_id,omitempty"`
	Secret         string `json:"secret,omitempty"`
	Realm          string `json:"realm,omitempty"`
	Target         string `json:"target,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewRefreshToken is the constructor for RefreshToken.
func NewRefreshToken(homeID, env, clientID, refreshToken, familyID string) RefreshToken {
	return RefreshToken{
		HomeAccountID:  homeID,
		Environment:    env,
		CredentialType: CredentialTypeRefreshToken,
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (rt RefreshToken) Key() string {
	var fourth = rt.FamilyID
	if fourth == "" {
		fourth = rt.ClientID
	}

	return strings.Join(
		[]string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth},
		CacheKeySeparator,
	)
}

func (rt RefreshToken) GetSecret() string {
	return rt.Secret
}

// TokenResponse is the information that is returned from a token endpoint during a token acquisition flow.
// TODO(jdoak): There is this tokenResponsePayload and TokenResponse.  This just needs a custom unmarshaller
// and we can get rid of having two.
type TokenResponse struct {
	OAuthResponseBase

	AccessToken    string
	RefreshToken   string
	IDToken        IDToken
	FamilyID       string
	GrantedScopes  []string
	DeclinedScopes []string
	ExpiresOn      time.Time
	ExtExpiresOn   time.Time
	rawClientInfo  string
	ClientInfo     ClientInfoJSONPayload

	AdditionalFields map[string]interface{}
}

// HasAccessToken checks if the TokenResponse has an access token.
func (tr TokenResponse) HasAccessToken() bool {
	return len(tr.AccessToken) > 0
}

// HasRefreshToken checks if the TokenResponse has an refresh token.
func (tr TokenResponse) HasRefreshToken() bool {
	return len(tr.RefreshToken) > 0
}

// GetHomeAccountIDFromClientInfo creates the home account ID for an account from the client info parameter.
func (tr TokenResponse) GetHomeAccountIDFromClientInfo() string {
	if tr.ClientInfo.UID == "" || tr.ClientInfo.Utid == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", tr.ClientInfo.UID, tr.ClientInfo.Utid)
}

// CreateTokenResponse creates a TokenResponse instance from the response from the token endpoint.
func CreateTokenResponse(authParameters AuthParametersInternal, resp *http.Response) (TokenResponse, error) {
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return TokenResponse{}, err
	}
	payload := TokenResponseJSONPayload{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return TokenResponse{}, err
	}

	if payload.Error != "" {
		return TokenResponse{}, fmt.Errorf("%s: %s", payload.Error, payload.ErrorDescription)
	}

	if payload.AccessToken == "" {
		// Access token is required in a token response
		return TokenResponse{}, errors.New("response is missing access_token")
	}

	rawClientInfo := payload.ClientInfo
	clientInfo := ClientInfoJSONPayload{}
	// Client info may be empty in some flows, e.g. certificate exchange.
	if len(rawClientInfo) > 0 {
		rawClientInfoDecoded, err := DecodeJWT(rawClientInfo)
		if err != nil {
			return TokenResponse{}, err
		}

		err = json.Unmarshal(rawClientInfoDecoded, &clientInfo)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	expiresOn := time.Now().Add(time.Second * time.Duration(payload.ExpiresIn))
	extExpiresOn := time.Now().Add(time.Second * time.Duration(payload.ExtExpiresIn))

	var (
		grantedScopes  []string
		declinedScopes []string
	)

	if len(payload.Scope) == 0 {
		// Per OAuth spec, if no scopes are returned, the response should be treated as if all scopes were granted
		// This behavior can be observed in client assertion flows, but can happen at any time, this check ensures we treat
		// those special responses properly
		// Link to spec: https://tools.ietf.org/html/rfc6749#section-3.3
		grantedScopes = authParameters.Scopes
	} else {
		grantedScopes = strings.Split(strings.ToLower(payload.Scope), scopeSeparator)
		declinedScopes = findDeclinedScopes(authParameters.Scopes, grantedScopes)
	}

	// Note: error dropped because ID tokens aren't always returned.
	// This used to be logged, but it just provides unhelpful log messages.
	idToken, _ := NewIDToken(payload.IDToken)

	tokenResponse := TokenResponse{
		OAuthResponseBase: payload.OAuthResponseBase,
		AccessToken:       payload.AccessToken,
		RefreshToken:      payload.RefreshToken,
		IDToken:           idToken,
		FamilyID:          payload.Foci,
		ExpiresOn:         expiresOn,
		ExtExpiresOn:      extExpiresOn,
		GrantedScopes:     grantedScopes,
		DeclinedScopes:    declinedScopes,
		rawClientInfo:     rawClientInfo,
		ClientInfo:        clientInfo,
	}
	return tokenResponse, nil
}

// CreateTokenResponse2 is like CreateTokenResponse except the input is slightly different.
// TODO(jdoak): Remove once we integrate ops package into the code.
func CreateTokenResponse2(authParameters AuthParametersInternal, payload TokenResponseJSONPayload) (TokenResponse, error) {
	if payload.Error != "" {
		return TokenResponse{}, fmt.Errorf("%s: %s", payload.Error, payload.ErrorDescription)
	}

	if payload.AccessToken == "" {
		// Access token is required in a token response
		return TokenResponse{}, errors.New("response is missing access_token")
	}

	rawClientInfo := payload.ClientInfo
	clientInfo := ClientInfoJSONPayload{}
	// Client info may be empty in some flows, e.g. certificate exchange.
	if len(rawClientInfo) > 0 {
		rawClientInfoDecoded, err := DecodeJWT(rawClientInfo)
		if err != nil {
			return TokenResponse{}, err
		}

		err = json.Unmarshal(rawClientInfoDecoded, &clientInfo)
		if err != nil {
			return TokenResponse{}, err
		}
	}

	expiresOn := time.Now().Add(time.Second * time.Duration(payload.ExpiresIn))
	extExpiresOn := time.Now().Add(time.Second * time.Duration(payload.ExtExpiresIn))

	var (
		grantedScopes  []string
		declinedScopes []string
	)

	if len(payload.Scope) == 0 {
		// Per OAuth spec, if no scopes are returned, the response should be treated as if all scopes were granted
		// This behavior can be observed in client assertion flows, but can happen at any time, this check ensures we treat
		// those special responses properly
		// Link to spec: https://tools.ietf.org/html/rfc6749#section-3.3
		grantedScopes = authParameters.Scopes
	} else {
		grantedScopes = strings.Split(strings.ToLower(payload.Scope), scopeSeparator)
		declinedScopes = findDeclinedScopes(authParameters.Scopes, grantedScopes)
	}

	// ID tokens aren't always returned, which is not a reportable error condition.
	// So we ignore it.
	idToken, _ := NewIDToken(payload.IDToken)

	tokenResponse := TokenResponse{
		OAuthResponseBase: payload.OAuthResponseBase,
		AccessToken:       payload.AccessToken,
		RefreshToken:      payload.RefreshToken,
		IDToken:           idToken,
		FamilyID:          payload.Foci,
		ExpiresOn:         expiresOn,
		ExtExpiresOn:      extExpiresOn,
		GrantedScopes:     grantedScopes,
		DeclinedScopes:    declinedScopes,
		rawClientInfo:     rawClientInfo,
		ClientInfo:        clientInfo,
	}
	return tokenResponse, nil
}

func findDeclinedScopes(requestedScopes []string, grantedScopes []string) []string {
	declined := []string{}
	grantedMap := map[string]bool{}
	for _, s := range grantedScopes {
		grantedMap[s] = true
	}
	// Comparing the requested scopes with the granted scopes to see if there are any scopes that have been declined.
	for _, r := range requestedScopes {
		if !grantedMap[r] {
			declined = append(declined, r)
		}
	}
	return declined
}
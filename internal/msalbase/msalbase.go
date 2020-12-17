// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	uuid "github.com/google/uuid"
	log "github.com/sirupsen/logrus"
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

// AuthorizationType represents the type of token flow.
type AuthorizationType int

// These are all the types of token flows
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

// AuthenticationResult contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type AuthenticationResult struct {
	Account        Account
	idToken        IDToken
	AccessToken    string
	ExpiresOn      time.Time
	GrantedScopes  []string
	DeclinedScopes []string
}

// CreateAuthenticationResultFromStorageTokenResponse creates an authenication result from a storage token response (which is generated from the cache).
func CreateAuthenticationResultFromStorageTokenResponse(storageTokenResponse StorageTokenResponse) (AuthenticationResult, error) {
	if storageTokenResponse.AccessToken == nil {
		return AuthenticationResult{}, errors.New("no access token present in cache")
	}

	account := storageTokenResponse.account
	accessToken := storageTokenResponse.AccessToken.GetSecret()
	expiresOn, err := ConvertStrUnixToUTCTime(storageTokenResponse.AccessToken.GetExpiresOn())
	if err != nil {
		return AuthenticationResult{},
			fmt.Errorf("token response from server is invalid because expires_in is set to %q", storageTokenResponse.AccessToken.GetExpiresOn())
	}
	grantedScopes := strings.Split(storageTokenResponse.AccessToken.GetScopes(), scopeSeparator)

	// Checking if there was an ID token in the cache; this will throw an error in the case of confidential client applications.
	var idToken IDToken
	if storageTokenResponse.IDToken != nil {
		idToken, err = NewIDToken(storageTokenResponse.IDToken.GetSecret())
		if err != nil {
			return AuthenticationResult{}, err
		}
	}
	return AuthenticationResult{account, idToken, accessToken, expiresOn, grantedScopes, nil}, nil
}

// CreateAuthenticationResult creates an AuthenticationResult.
// TODO(jdoak): Make this a method on TokenResponse() that takes only 1 arge, Account.
func CreateAuthenticationResult(tokenResponse TokenResponse, account Account) (AuthenticationResult, error) {
	if len(tokenResponse.declinedScopes) > 0 {
		return AuthenticationResult{}, fmt.Errorf("token response failed because declined scopes are present: %s", strings.Join(tokenResponse.declinedScopes, ","))
	}
	return AuthenticationResult{
		Account:       account,
		idToken:       tokenResponse.IDToken,
		AccessToken:   tokenResponse.AccessToken,
		ExpiresOn:     tokenResponse.ExpiresOn,
		GrantedScopes: tokenResponse.GrantedScopes,
	}, nil
}

//GetAccessToken returns the access token of the authentication result
func (ar AuthenticationResult) GetAccessToken() string {
	return ar.AccessToken
}

// GetAccount returns the account of the authentication result
func (ar AuthenticationResult) GetAccount() Account {
	return ar.Account
}

// ClientCredentialType refers to the type of credential used for confidential client flows.
type ClientCredentialType int

// Values for ClientCredentialType.
// TODO(jdoak): This looks suspect.
const (
	ClientCredentialSecret ClientCredentialType = iota
	ClientCredentialAssertion
)

// ClientCredential represents the credential used in confidential client flows.
type ClientCredential struct {
	clientSecret    string
	clientAssertion *ClientAssertion
	credentialType  ClientCredentialType
}

// CreateClientCredentialFromSecret creates a ClientCredential instance from a secret.
func CreateClientCredentialFromSecret(secret string) (ClientCredential, error) {
	if secret == "" {
		return ClientCredential{}, errors.New("client secret can't be blank")
	}
	return ClientCredential{clientSecret: secret, clientAssertion: nil, credentialType: ClientCredentialSecret}, nil
}

// CreateClientCredentialFromCertificate creates a ClientCredential instance from a certificate (thumbprint and private key).
func CreateClientCredentialFromCertificate(thumbprint string, key []byte) (ClientCredential, error) {
	if thumbprint == "" || len(key) == 0 {
		return ClientCredential{}, errors.New("thumbprint can't be blank or private key can't be empty")
	}
	return ClientCredential{
		clientAssertion: CreateClientAssertionFromCertificate(thumbprint, key),
		credentialType:  ClientCredentialAssertion,
	}, nil
}

// CreateClientCredentialFromCertificateObject creates a ClientCredential instance from a ClientCertificate instance.
func CreateClientCredentialFromCertificateObject(cert *ClientCertificate) ClientCredential {
	return ClientCredential{
		clientAssertion: CreateClientAssertionFromCertificateObject(cert),
		credentialType:  ClientCredentialAssertion,
	}
}

// CreateClientCredentialFromAssertion creates a ClientCredential instance from an assertion JWT.
func CreateClientCredentialFromAssertion(assertion string) (ClientCredential, error) {
	if assertion == "" {
		return ClientCredential{}, errors.New("assertion can't be blank")
	}
	return ClientCredential{
		clientAssertion: CreateClientAssertionFromJWT(assertion),
		credentialType:  ClientCredentialAssertion,
	}, nil
}

// GetCredentialType returns the type of the ClientCredential.
func (cred ClientCredential) GetCredentialType() ClientCredentialType {
	return cred.credentialType
}

// GetSecret returns the secret of ClientCredential instance.
func (cred ClientCredential) GetSecret() string {
	return cred.clientSecret
}

// GetAssertion returns the assertion of the ClientCredential instance.
func (cred ClientCredential) GetAssertion() *ClientAssertion {
	return cred.clientAssertion
}

// DeviceCodeResult stores the response from the STS device code endpoint.
type DeviceCodeResult struct {
	userCode        string
	deviceCode      string
	verificationURL string
	expiresOn       time.Time
	interval        int
	message         string
	clientID        string
	scopes          []string
}

// CreateDeviceCodeResult creates a DeviceCodeResult instance.
func CreateDeviceCodeResult(userCode, deviceCode, verificationURL string, expiresOn time.Time, interval int, message, clientID string, scopes []string) DeviceCodeResult {
	return DeviceCodeResult{userCode, deviceCode, verificationURL, expiresOn, interval, message, clientID, scopes}
}

func (dcr DeviceCodeResult) String() string {
	return fmt.Sprintf("UserCode: (%v)\nDeviceCode: (%v)\nURL: (%v)\nMessage: (%v)\n", dcr.userCode, dcr.deviceCode, dcr.verificationURL, dcr.message)

}

// GetUserCode returns the code the user needs to provide when authentication at the verification URI.
func (dcr DeviceCodeResult) GetUserCode() string {
	return dcr.userCode
}

// GetDeviceCode returns the code used in the access token request.
func (dcr DeviceCodeResult) GetDeviceCode() string {
	return dcr.deviceCode
}

// GetVerificationURL returns the URL where user can authenticate.
func (dcr DeviceCodeResult) GetVerificationURL() string {
	return dcr.verificationURL
}

// GetExpiresOn returns the expiration time of device code in seconds.
func (dcr DeviceCodeResult) GetExpiresOn() time.Time {
	return dcr.expiresOn
}

// GetInterval returns the interval at which the STS should be polled at.
func (dcr DeviceCodeResult) GetInterval() int {
	return dcr.interval
}

// GetMessage returns the message which should be displayed to the user.
func (dcr DeviceCodeResult) GetMessage() string {
	return dcr.message
}

// GetClientID returns the UUID issued by the authorization server for your application.
func (dcr DeviceCodeResult) GetClientID() string {
	return dcr.clientID
}

// GetScopes returns the scopes used to request access a protected API.
func (dcr DeviceCodeResult) GetScopes() []string {
	return dcr.scopes
}

// StorageTokenResponse mimics a token response that was pulled from the cache.
type StorageTokenResponse struct {
	RefreshToken Credential
	AccessToken  accessTokenProvider
	IDToken      Credential
	account      Account
}

// CreateStorageTokenResponse creates a token response from cache.
func CreateStorageTokenResponse(accessToken accessTokenProvider, refreshToken Credential, idToken Credential, account Account) StorageTokenResponse {
	return StorageTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		account:      account,
	}
}

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

type tokenResponseJSONPayload struct {
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

// TokenResponse is the information that is returned from a token endpoint during a token acquisition flow.
type TokenResponse struct {
	baseResponse   OAuthResponseBase
	AccessToken    string
	RefreshToken   string
	IDToken        IDToken
	FamilyID       string
	GrantedScopes  []string
	declinedScopes []string
	ExpiresOn      time.Time
	ExtExpiresOn   time.Time
	rawClientInfo  string
	ClientInfo     ClientInfoJSONPayload
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
	baseResponse, err := CreateOAuthResponseBase(resp.StatusCode, body)
	if err != nil {
		return TokenResponse{}, err
	}
	payload := tokenResponseJSONPayload{}
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return TokenResponse{}, err
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

	idToken, err := NewIDToken(payload.IDToken)
	if err != nil {
		// ID tokens aren't always returned, so the error is just logged
		// TODO(jdoak): we should probably remove this. Either this is an error or isn't.
		log.Errorf("ID Token error: %v", err)
	}

	tokenResponse := TokenResponse{
		baseResponse:   baseResponse,
		AccessToken:    payload.AccessToken,
		RefreshToken:   payload.RefreshToken,
		IDToken:        idToken,
		FamilyID:       payload.Foci,
		ExpiresOn:      expiresOn,
		ExtExpiresOn:   extExpiresOn,
		GrantedScopes:  grantedScopes,
		declinedScopes: declinedScopes,
		rawClientInfo:  rawClientInfo,
		ClientInfo:     clientInfo,
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

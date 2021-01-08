package accesstokens

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

type TokenResponseJSONPayload struct {
	authority.OAuthResponseBase

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
	// This means changing decodeJWT().
	ClientInfo string `json:"client_info"`

	AdditionalFields map[string]interface{}
}

// ClientInfoJSONPayload is used to create a Home Account ID for an account.
type ClientInfoJSONPayload struct {
	UID  string `json:"uid"`
	Utid string `json:"utid"`

	AdditionalFields map[string]interface{}
}

// IDToken consists of all the information used to validate a user.
// https://docs.microsoft.com/azure/active-directory/develop/id-tokens .
type IDToken struct {
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Name              string `json:"name,omitempty"`
	Oid               string `json:"oid,omitempty"`
	TenantID          string `json:"tid,omitempty"`
	Subject           string `json:"sub,omitempty"`
	UPN               string `json:"upn,omitempty"`
	Email             string `json:"email,omitempty"`
	AlternativeID     string `json:"alternative_id,omitempty"`
	Issuer            string `json:"iss,omitempty"`
	Audience          string `json:"aud,omitempty"`
	ExpirationTime    int64  `json:"exp,omitempty"`
	IssuedAt          int64  `json:"iat,omitempty"`
	NotBefore         int64  `json:"nbf,omitempty"`
	RawToken          string

	AdditionalFields map[string]interface{}
}

// NewIDToken creates an ID token instance from a JWT.
func NewIDToken(jwt string) (IDToken, error) {
	jwtArr := strings.Split(jwt, ".")
	if len(jwtArr) < 2 {
		return IDToken{}, errors.New("id token returned from server is invalid")
	}
	jwtPart := jwtArr[1]
	jwtDecoded, err := decodeJWT(jwtPart)
	if err != nil {
		return IDToken{}, err
	}
	idToken := IDToken{}
	err = json.Unmarshal(jwtDecoded, &idToken)
	if err != nil {
		return IDToken{}, err
	}
	idToken.RawToken = jwt
	return idToken, nil
}

// IsZero indicates if the IDToken is the zero value.
func (i IDToken) IsZero() bool {
	v := reflect.ValueOf(i)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsZero() {
			return false
		}
	}
	return true
}

// GetLocalAccountID extracts an account's local account ID from an ID token.
func (i IDToken) GetLocalAccountID() string {
	if i.Oid != "" {
		return i.Oid
	}
	return i.Subject
}

// TokenResponse is the information that is returned from a token endpoint during a token acquisition flow.
// TODO(jdoak): There is this tokenResponsePayload and TokenResponse.  This just needs a custom unmarshaller
// and we can get rid of having two.
type TokenResponse struct {
	authority.OAuthResponseBase

	AccessToken    string
	RefreshToken   string
	IDToken        IDToken
	FamilyID       string
	GrantedScopes  []string
	DeclinedScopes []string
	ExpiresOn      time.Time
	ExtExpiresOn   time.Time
	RawClientInfo  string
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

// NewTokenResponse creates a TokenResponse instance from the response from the token endpoint.
func NewTokenResponse(authParameters authority.AuthParams, payload TokenResponseJSONPayload) (TokenResponse, error) {
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
		rawClientInfoDecoded, err := decodeJWT(rawClientInfo)
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
		grantedScopes = strings.Split(strings.ToLower(payload.Scope), " ")
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
		RawClientInfo:     rawClientInfo,
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

// decodeJWT decodes a JWT and converts it to a byte array representing a JSON object
// Adapted from MSAL Python and https://stackoverflow.com/a/31971780 .
func decodeJWT(data string) ([]byte, error) {
	if i := len(data) % 4; i != 0 {
		data += strings.Repeat("=", 4-i)
	}
	return base64.StdEncoding.DecodeString(data)
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
		CredentialType: "RefreshToken",
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
		shared.CacheKeySeparator,
	)
}

func (rt RefreshToken) GetSecret() string {
	return rt.Secret
}

// DeviceCodeResult stores the response from the STS device code endpoint.
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

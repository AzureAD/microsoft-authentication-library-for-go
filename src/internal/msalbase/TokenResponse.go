package msalbase

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type tokenResponseJSONPayload struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExtExpiresIn int64  `json:"ext_expires_in"`
	Foci         string `json:"foci"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token"`
	ClientInfo   string `json:"client_info"`
}

type clientInfoJSONPayload struct {
	uid  string `json:"uid"`
	utid string `json:"utid"`
}

type TokenResponse struct {
	baseResponse   *OAuthResponseBase
	accessToken    string
	refreshToken   string
	idToken        *IDToken
	familyID       string
	grantedScopes  []string
	declinedScopes []string
	expiresOn      time.Time
	extExpiresOn   time.Time
	rawClientInfo  string
	clientInfo     *clientInfoJSONPayload
}

func (tr *TokenResponse) HasAccessToken() bool {
	return len(tr.accessToken) > 0
}

func (tr *TokenResponse) HasRefreshToken() bool {
	return len(tr.refreshToken) > 0
}

func (tr *TokenResponse) IsAuthorizationPending() bool {
	return tr.baseResponse.Error == "authorization_pending"
}

func (tr *TokenResponse) GetAccessToken() string {
	return tr.accessToken
}

func (tr *TokenResponse) GetRefreshToken() string {
	return tr.refreshToken
}

func (tr *TokenResponse) GetIDToken() *IDToken {
	return tr.idToken
}

func (tr *TokenResponse) GetGrantedScopes() []string {
	return tr.grantedScopes
}

func (tr *TokenResponse) GetDeclinedScopes() []string {
	return tr.declinedScopes
}

func (tr *TokenResponse) GetRawClientInfo() string {
	return tr.rawClientInfo
}

func (tr *TokenResponse) GetExpiresOn() time.Time {
	return tr.expiresOn
}

func (tr *TokenResponse) GetExtendedExpiresOn() time.Time {
	return tr.extExpiresOn
}

func CreateTokenResponse(authParameters *AuthParametersInternal, responseCode int, responseData string) (*TokenResponse, error) {
	baseResponse, err := CreateOAuthResponseBase(responseCode, responseData)
	if err != nil {
		return nil, err
	}

	payload := &tokenResponseJSONPayload{}
	err = json.Unmarshal([]byte(responseData), payload)
	if err != nil {
		return nil, err
	}

	if payload.AccessToken == "" {
		// AccessToken is required, error out
		return nil, errors.New("response is missing access_token")
	}

	rawClientInfo := payload.ClientInfo
	clientInfo := &clientInfoJSONPayload{}

	if len(rawClientInfo) > 0 {
		// Client info may be empty in some flows, e.g. certificate exchange.
		rawClientInfoDecoded, err := base64.RawStdEncoding.DecodeString(rawClientInfo)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(rawClientInfoDecoded, clientInfo)
		if err != nil {
			return nil, err
		}
	}

	expiresOn := time.Now().Add(time.Second * time.Duration(payload.ExpiresIn))
	extExpiresOn := time.Now().Add(time.Second * time.Duration(payload.ExtExpiresIn))

	grantedScopes := []string{}
	declinedScopes := []string{}

	if len(payload.Scope) == 0 {
		// Per OAuth spec, if no scopes are returned, the response should be treated as if all scopes were granted
		// This behavior can be observed in client assertion flows, but can happen at any time, this check ensures we treat
		// those special responses properly
		// Link to spec: https://tools.ietf.org/html/rfc6749#section-3.3
		grantedScopes = authParameters.GetScopes()
	} else {
		grantedScopes = strings.Split(payload.Scope, " ")
		declinedScopes = findDeclinedScopes(authParameters.GetScopes(), grantedScopes)
	}

	idToken, err := CreateIDToken(payload.IDToken)
	if err != nil {
		return nil, err
	}

	tokenResponse := &TokenResponse{
		baseResponse:   baseResponse,
		accessToken:    payload.AccessToken,
		refreshToken:   payload.RefreshToken,
		idToken:        idToken,
		familyID:       payload.Foci,
		expiresOn:      expiresOn,
		extExpiresOn:   extExpiresOn,
		grantedScopes:  grantedScopes,
		declinedScopes: declinedScopes}
	return tokenResponse, nil
}

func findDeclinedScopes(requestedScopes []string, grantedScopes []string) []string {
	declined := []string{}

	grantedMap := map[string]bool{}
	for _, s := range grantedScopes {
		grantedMap[s] = true
	}

	for _, r := range requestedScopes {
		if !grantedMap[r] {
			declined = append(declined, r)
		}
	}

	return declined
}

func CreateTokenResponseFromParts(idToken *IDToken, accessToken *Credential, refreshToken *Credential) (*TokenResponse, error) {

	var idt *IDToken
	accessTokenSecret := ""
	refreshTokenSecret := ""
	grantedScopes := []string{}

	if idToken != nil {
		idt = idToken
	} else {
		idt, _ = CreateIDToken("")
	}

	if accessToken != nil {
		accessTokenSecret = accessToken.GetSecret()
		// todo: fill this in...
		// _expiresOn = TimeUtils::ToTimePoint(accessToken->GetExpiresOn());
		// _extendedExpiresOn = TimeUtils::ToTimePoint(accessToken->GetExtendedExpiresOn());
		grantedScopes = strings.Split(accessToken.GetScopes(), " ")
	}

	if refreshToken != nil {
		refreshTokenSecret = refreshToken.GetSecret()
	}

	tokenResponse := &TokenResponse{idToken: idt, accessToken: accessTokenSecret, refreshToken: refreshTokenSecret, grantedScopes: grantedScopes}
	return tokenResponse, nil
}

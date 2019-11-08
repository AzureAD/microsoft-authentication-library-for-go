// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type AuthorizationType int

const (
	AuthorizationTypeNone                  AuthorizationType = iota
	AuthorizationTypeUsernamePassword                        = iota
	AuthorizationTypeWindowsIntegratedAuth                   = iota
	AuthorizationTypeAuthCode                                = iota
	AuthorizationTypeInteractive                             = iota
	AuthorizationTypeCertificate                             = iota
	AuthorizationTypeDeviceCode                              = iota
	AuthorizationTypeRefreshTokenExchange                    = iota
)

type AuthParametersInternal struct {
	authorityInfo     *AuthorityInfo
	correlationID     string
	endpoints         *AuthorityEndpoints
	clientID          string
	redirecturi       string
	homeaccountid     string
	username          string
	password          string
	scopes            []string
	authorizationType AuthorizationType
}

func CreateAuthParametersInternal(clientID string, authorityInfo *AuthorityInfo) *AuthParametersInternal {
	p := &AuthParametersInternal{clientID: clientID, authorityInfo: authorityInfo}
	return p
}

func (ap *AuthParametersInternal) SetScopes(scopes []string) {
	ap.scopes = scopes
}

func (ap *AuthParametersInternal) GetScopes() []string {
	return ap.scopes
}

func (ap *AuthParametersInternal) GetClientID() string {
	return ap.clientID
}

func (ap *AuthParametersInternal) GetCorrelationID() string {
	return ap.correlationID
}

func (ap *AuthParametersInternal) GetAuthorityEndpoints() *AuthorityEndpoints {
	return ap.endpoints
}

func (ap *AuthParametersInternal) SetAuthorityEndpoints(authorityEndpoints *AuthorityEndpoints) {
	ap.endpoints = authorityEndpoints
}

func (ap *AuthParametersInternal) GetUsername() string {
	return ap.username
}

func (ap *AuthParametersInternal) SetUsername(username string) {
	ap.username = username
}

func (ap *AuthParametersInternal) GetPassword() string {
	return ap.password
}

func (ap *AuthParametersInternal) SetPassword(password string) {
	ap.password = password
}

func (ap *AuthParametersInternal) GetAuthorityInfo() *AuthorityInfo {
	return ap.authorityInfo
}

func (ap *AuthParametersInternal) GetRedirectURI() string {
	return ap.redirecturi
}

func (ap *AuthParametersInternal) GetAuthorizationType() AuthorizationType {
	return ap.authorizationType
}

func (ap *AuthParametersInternal) SetAuthorizationType(authType AuthorizationType) {
	ap.authorizationType = authType
}

func (ap *AuthParametersInternal) GetHomeAccountID() string {
	return ap.homeaccountid
}

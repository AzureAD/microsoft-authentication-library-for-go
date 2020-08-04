// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

//AuthorizationType represents the type of token flow
type AuthorizationType int

//These are all the types of token flows
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

//AuthParametersInternal represents the parameters used for authorization for token acquisition
type AuthParametersInternal struct {
	AuthorityInfo     *AuthorityInfo
	CorrelationID     string
	Endpoints         *AuthorityEndpoints
	ClientID          string
	Redirecturi       string
	HomeaccountID     string
	Username          string
	Password          string
	Scopes            []string
	AuthorizationType AuthorizationType
}

//CreateAuthParametersInternal creates an authorization parameters object
func CreateAuthParametersInternal(clientID string, authorityInfo *AuthorityInfo) *AuthParametersInternal {
	p := &AuthParametersInternal{ClientID: clientID, AuthorityInfo: authorityInfo}
	return p
}

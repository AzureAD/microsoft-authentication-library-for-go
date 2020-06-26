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

func CreateAuthParametersInternal(clientID string, authorityInfo *AuthorityInfo) *AuthParametersInternal {
	p := &AuthParametersInternal{ClientID: clientID, AuthorityInfo: authorityInfo}
	return p
}

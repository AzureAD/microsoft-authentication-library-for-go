// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

type applicationCommonParameters struct {
	clientID      string
	authorityInfo msalbase.AuthorityInfo
}

func createApplicationCommonParameters(clientID, authorityURI string) (*applicationCommonParameters, error) {
	a, err := msalbase.CreateAuthorityInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		return nil, err
	}
	return &applicationCommonParameters{
		clientID:      clientID,
		authorityInfo: a,
	}, nil
}

func (p *applicationCommonParameters) validate() error {
	return nil
}

func (p *applicationCommonParameters) createAuthenticationParameters() msalbase.AuthParametersInternal {
	return msalbase.CreateAuthParametersInternal(p.clientID, p.authorityInfo)
}

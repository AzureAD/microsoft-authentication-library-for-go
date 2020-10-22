// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

type applicationCommonParameters struct {
	clientID      string
	authorityInfo *msalbase.AuthorityInfo
}

func createApplicationCommonParameters(clientID string) *applicationCommonParameters {
	p := &applicationCommonParameters{
		clientID: clientID,
	}
	return p
}

func (p *applicationCommonParameters) setAadAuthority(authorityURI string) error {
	authorityInfo, err := msalbase.CreateAuthorityInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		return err
	}
	p.authorityInfo = authorityInfo
	return nil
}

func (p *applicationCommonParameters) validate() error {
	return nil
}

func (p *applicationCommonParameters) createAuthenticationParameters() *msalbase.AuthParametersInternal {
	params := msalbase.CreateAuthParametersInternal(p.clientID, p.authorityInfo)
	return params
}

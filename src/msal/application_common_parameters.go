// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type applicationCommonParameters struct {
	clientID      string
	authorityInfo *msalbase.AuthorityInfo
}

// CreateApplicationCommonParameters stuff
func createApplicationCommonParameters(clientID string) *applicationCommonParameters {
	p := &applicationCommonParameters{
		clientID: clientID,
	}
	return p
}

func (p *applicationCommonParameters) SetAadAuthority(authorityURI string) error {
	authorityInfo, err := msalbase.CreateAuthorityInfoFromAuthorityUri(authorityURI, true)
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
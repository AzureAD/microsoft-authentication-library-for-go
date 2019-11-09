// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "internal/msalbase"

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

func (p *applicationCommonParameters) SetAadAuthority(authorityURI string) {
	// todo: need to propagate errors here...
	// perhaps collect any errors along the way and surface them in validate()?
	authorityInfo, _ := msalbase.CreateAuthorityInfoFromAuthorityUri(authorityURI, true)
	p.authorityInfo = authorityInfo
}

func (p *applicationCommonParameters) GetClientID() string {
	return p.clientID
}

func (p *applicationCommonParameters) validate() error {
	return nil
}

func (p *applicationCommonParameters) createAuthenticationParameters() *msalbase.AuthParametersInternal {
	params := msalbase.CreateAuthParametersInternal(p.clientID, p.authorityInfo)
	return params
}

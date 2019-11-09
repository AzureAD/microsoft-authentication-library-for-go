// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "internal/msalbase"

// PublicClientApplicationParameters stuff
type PublicClientApplicationParameters struct {
	commonParameters *applicationCommonParameters
}

// CreatePublicClientApplicationParameters stuff
func CreatePublicClientApplicationParameters(clientID string) *PublicClientApplicationParameters {
	commonParameters := createApplicationCommonParameters(clientID)
	p := &PublicClientApplicationParameters{commonParameters}
	return p
}

func (p *PublicClientApplicationParameters) SetAadAuthority(authorityURI string) {
	p.commonParameters.SetAadAuthority(authorityURI)
}

func (p *PublicClientApplicationParameters) validate() error {
	err := p.commonParameters.validate()
	return err
}

func (p *PublicClientApplicationParameters) createAuthenticationParameters() *msalbase.AuthParametersInternal {
	params := p.commonParameters.createAuthenticationParameters()
	return params
}

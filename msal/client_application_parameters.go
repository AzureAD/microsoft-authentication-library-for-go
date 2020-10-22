// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

type clientApplicationParameters struct {
	commonParameters *applicationCommonParameters
}

func createClientApplicationParameters(clientID string) *clientApplicationParameters {
	commonParameters := createApplicationCommonParameters(clientID)
	p := &clientApplicationParameters{commonParameters}
	return p
}

func (p *clientApplicationParameters) setAadAuthority(authorityURI string) {
	p.commonParameters.setAadAuthority(authorityURI)
}

func (p *clientApplicationParameters) validate() error {
	err := p.commonParameters.validate()
	return err
}

func (p *clientApplicationParameters) createAuthenticationParameters() *msalbase.AuthParametersInternal {
	params := p.commonParameters.createAuthenticationParameters()
	return params
}

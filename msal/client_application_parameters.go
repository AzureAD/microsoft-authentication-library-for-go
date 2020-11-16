// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"

// TODO(jdoak): determine in the long run if this is even needed. Looks like
// a hold over from a language conversion.  This doesn't do anything but use
// applicationCommonParameters, which probably means it has no validity as its
// own type.
type clientApplicationParameters struct {
	commonParameters *applicationCommonParameters
}

func createClientApplicationParameters(clientID, authorityURI string) (*clientApplicationParameters, error) {
	// NOTE: I moved setADDAuthority here.  It called a method that was only
	// used on the output of this function, which is only called here.  It also
	// ignored the error output. That seems buggy (anytime you ignore an error, must document why).
	cp, err := createApplicationCommonParameters(clientID, authorityURI)
	if err != nil {
		return nil, err
	}
	return &clientApplicationParameters{
		commonParameters: cp,
	}, nil
}

func (p *clientApplicationParameters) validate() error {
	err := p.commonParameters.validate()
	return err
}

func (p *clientApplicationParameters) createAuthenticationParameters() msalbase.AuthParametersInternal {
	return p.commonParameters.createAuthenticationParameters()
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "internal/msalbase"

type acquireTokenCommonParameters struct {
	scopes []string
}

func createAcquireTokenCommonParameters(scopes []string) *acquireTokenCommonParameters {
	p := &acquireTokenCommonParameters{
		scopes: scopes,
	}
	return p
}

func (p *acquireTokenCommonParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	authParams.SetScopes(p.scopes)
}

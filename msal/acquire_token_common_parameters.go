// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type acquireTokenCommonParameters struct {
	scopes []string
}

func createAcquireTokenCommonParameters(scopes []string) acquireTokenCommonParameters {
	loweredScopes := []string{}
	for _, s := range scopes {
		s = strings.ToLower(s)
		loweredScopes = append(loweredScopes, s)
	}
	return acquireTokenCommonParameters{
		scopes: loweredScopes,
	}
}

func (p *acquireTokenCommonParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	authParams.Scopes = p.scopes
}

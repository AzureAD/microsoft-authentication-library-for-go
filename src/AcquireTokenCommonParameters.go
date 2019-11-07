package msalgo

import "github.com/markzuber/msalgo/internal/msalbase"

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

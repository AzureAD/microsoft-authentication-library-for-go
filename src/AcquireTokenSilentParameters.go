package msalgo

import "github.com/markzuber/msalgo/internal/msalbase"

// AcquireTokenSilentParameters stuff
type AcquireTokenSilentParameters struct {
	commonParameters *acquireTokenCommonParameters
}

// CreateAcquireTokenSilentParameters stuff
func CreateAcquireTokenSilentParameters(scopes []string, username string, password string) *AcquireTokenSilentParameters {
	p := &AcquireTokenSilentParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
	return p
}

func (p *AcquireTokenSilentParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeRefreshTokenExchange)
}

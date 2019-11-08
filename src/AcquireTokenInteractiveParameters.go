package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenInteractiveParameters stuff
type AcquireTokenInteractiveParameters struct {
	commonParameters *acquireTokenCommonParameters
}

// CreateAcquireTokenInteractiveParameters stuff
func CreateAcquireTokenInteractiveParameters(scopes []string, username string, password string) *AcquireTokenInteractiveParameters {
	p := &AcquireTokenInteractiveParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
	}
	return p
}

func (p *AcquireTokenInteractiveParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeInteractive)
}

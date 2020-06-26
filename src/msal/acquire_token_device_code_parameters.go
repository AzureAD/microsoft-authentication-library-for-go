// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AcquireTokenDeviceCodeParameters stuff
type AcquireTokenDeviceCodeParameters struct {
	commonParameters   *acquireTokenCommonParameters
	deviceCodeCallback func(IDeviceCodeResult)
	cancelCtx          context.Context
}

// CreateAcquireTokenDeviceCodeParameters stuff
func CreateAcquireTokenDeviceCodeParameters(cancelCtx context.Context, scopes []string,
	deviceCodeCallback func(IDeviceCodeResult)) *AcquireTokenDeviceCodeParameters {
	p := &AcquireTokenDeviceCodeParameters{
		commonParameters:   createAcquireTokenCommonParameters(scopes),
		deviceCodeCallback: deviceCodeCallback,
		cancelCtx:          cancelCtx,
	}
	return p
}

func (p *AcquireTokenDeviceCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeDeviceCode
}

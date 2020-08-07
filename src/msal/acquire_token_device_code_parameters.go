// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AcquireTokenDeviceCodeParameters contains the parameters required to acquire an access token using the device code flow
type AcquireTokenDeviceCodeParameters struct {
	commonParameters   *acquireTokenCommonParameters
	deviceCodeCallback func(DeviceCodeResultInterfacer)
	cancelCtx          context.Context
}

// CreateAcquireTokenDeviceCodeParameters creates an AcquireTokenDeviceCodeParameters instance
func CreateAcquireTokenDeviceCodeParameters(cancelCtx context.Context, scopes []string,
	deviceCodeCallback func(DeviceCodeResultInterfacer)) *AcquireTokenDeviceCodeParameters {
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

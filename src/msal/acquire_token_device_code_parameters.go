// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"context"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// AcquireTokenDeviceCodeParameters contains the parameters required to acquire an access token using the device code flow.
type AcquireTokenDeviceCodeParameters struct {
	commonParameters   *acquireTokenCommonParameters
	deviceCodeCallback func(DeviceCodeResultProvider)
	cancelCtx          context.Context
}

// CreateAcquireTokenDeviceCodeParameters creates an AcquireTokenDeviceCodeParameters instance.
// Pass in the scopes required, a context object that can be use to signal when the request should be canceled,
// as well as a function that can take in a DeviceCodeResultProvider as a parameter. This function should
// be doing something with this DeviceCodeProvider so that the user can enter the device code at the URL.
func CreateAcquireTokenDeviceCodeParameters(cancelCtx context.Context, scopes []string,
	deviceCodeCallback func(DeviceCodeResultProvider)) *AcquireTokenDeviceCodeParameters {
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

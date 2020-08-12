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
// This flow is designed for devices that do not have access to a browser or have input constraints.
// The authorization server issues a DeviceCode object with a verification code, an end-user code, and the end-user verification URI.
// The DeviceCode object is provided through the DeviceCodeResultProvider callback, and the end-user should be instructed to use
// another device to navigate to the verification URI to input credentials. Since the client cannot receive incoming requests,
// MSAL polls the authorization server repeatedly until the end-user completes input of credentials. Use cancelCtx to cancel the polling.
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

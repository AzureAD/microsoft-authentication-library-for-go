// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenDeviceCodeParameters stuff
type AcquireTokenDeviceCodeParameters struct {
	commonParameters   *acquireTokenCommonParameters
	deviceCodeCallback func(IDeviceCodeResult)
	cancelChannel      chan bool
}

// CreateAcquireTokenDeviceCodeParameters stuff
func CreateAcquireTokenDeviceCodeParameters(scopes []string,
	deviceCodeCallback func(IDeviceCodeResult),
	cancelChannel chan bool) *AcquireTokenDeviceCodeParameters {
	p := &AcquireTokenDeviceCodeParameters{
		commonParameters:   createAcquireTokenCommonParameters(scopes),
		deviceCodeCallback: deviceCodeCallback,
		cancelChannel:      cancelChannel,
	}
	return p
}

func (p *AcquireTokenDeviceCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeDeviceCode)
}

func (p *AcquireTokenDeviceCodeParameters) InternalCallback(dcr *msalbase.DeviceCodeResult) {
	var returnedDCR IDeviceCodeResult
	returnedDCR = dcr
	p.deviceCodeCallback(returnedDCR)
}

func (p *AcquireTokenDeviceCodeParameters) GetCancelChannel() chan bool {
	return p.cancelChannel
}

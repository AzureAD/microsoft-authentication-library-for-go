// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenDeviceCodeParameters stuff
type AcquireTokenDeviceCodeParameters struct {
	commonParameters   *acquireTokenCommonParameters
	deviceCodeCallback func(IDeviceCodeResult)
}

// CreateAcquireTokenDeviceCodeParameters stuff
func CreateAcquireTokenDeviceCodeParameters(scopes []string, deviceCodeCallback func(IDeviceCodeResult)) *AcquireTokenDeviceCodeParameters {
	p := &AcquireTokenDeviceCodeParameters{
		commonParameters:   createAcquireTokenCommonParameters(scopes),
		deviceCodeCallback: deviceCodeCallback,
	}
	return p
}

func (p *AcquireTokenDeviceCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeDeviceCode)
}

/*
func (p *AcquireTokenDeviceCodeParameters) GetDeviceCodeResult() *msalbase.DeviceCodeResult {
	return p.deviceCodeResult
}*/

func (p *AcquireTokenDeviceCodeParameters) InternalCallback(dcr *msalbase.DeviceCodeResult) {
	var returnedDCR IDeviceCodeResult
	returnedDCR = dcr
	p.deviceCodeCallback(returnedDCR)
}

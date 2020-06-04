// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

// AcquireTokenDeviceCodeParameters stuff
type AcquireTokenDeviceCodeParameters struct {
	commonParameters *acquireTokenCommonParameters
	deviceCodeResult *msalbase.DeviceCodeResult
}

// CreateAcquireTokenDeviceCodeParameters stuff
func CreateAcquireTokenDeviceCodeParameters(scopes []string) *AcquireTokenDeviceCodeParameters {
	p := &AcquireTokenDeviceCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		deviceCodeResult: &msalbase.DeviceCodeResult{},
	}
	return p
}

func (p *AcquireTokenDeviceCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.SetAuthorizationType(msalbase.AuthorizationTypeDeviceCode)
}

func (p *AcquireTokenDeviceCodeParameters) GetDeviceCodeResult() *msalbase.DeviceCodeResult {
	return p.deviceCodeResult
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

type AcquireTokenClientAssertionParameters struct {
	commonParameters *acquireTokenCommonParameters
	clientAssertion string
}


func CreateAcquireTokenClientAssertionParameters(scopes []string,
	clientAssertion string) *AcquireTokenClientAssertionParameters {
	params := &AcquireTokenClientAssertionParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		clientAssertion: clientAssertion,
	}
	return params
}

func (p *AcquireTokenClientAssertionParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.AuthorizationType = msalbase.AuthorizationTypeClientCredentials
}

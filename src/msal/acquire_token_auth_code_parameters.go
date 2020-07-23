// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

// AcquireTokenAuthCodeParameters contains the parameters required to acquire an access token using the auth code flow
type AcquireTokenAuthCodeParameters struct {
	commonParameters *acquireTokenCommonParameters
	redirectURI      string
	Code             string
	codeChallenge    string
	ClientSecret     string
	CertThumbprint   string
	CertKey          []byte
	ClientAssertion  string
	RequestType      requests.AuthCodeRequestType
}

// CreateAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance
func CreateAcquireTokenAuthCodeParameters(scopes []string,
	redirectURI string,
	codeChallenge string) *AcquireTokenAuthCodeParameters {
	p := &AcquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
		codeChallenge:    codeChallenge,
		RequestType:      requests.AuthCodePublicClient,
	}
	return p
}

// CreateAcquireTokenAuthCodeParameters creates an AcquireTokenAuthCodeParameters instance
func CreateAcquireTokenAuthCodeParametersWithClientSecret(scopes []string,
	redirectURI string,
	codeChallenge string,
	clientSecret string) *AcquireTokenAuthCodeParameters {
	p := &AcquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
		codeChallenge:    codeChallenge,
		ClientSecret:     clientSecret,
		RequestType:      requests.AuthCodeClientSecret,
	}
	return p
}

func CreateAcquireAuthCodeParametersWithCertificate(scopes []string,
	redirectURI string,
	codeChallenge string,
	thumbprint string,
	key []byte) *AcquireTokenAuthCodeParameters {
	p := &AcquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
		codeChallenge:    codeChallenge,
		CertThumbprint:   thumbprint,
		CertKey:          key,
		RequestType:      requests.AuthCodeClientAssertion,
	}
	return p
}

func CreateAcquireAuthCodeParametersWithAssertion(scopes []string,
	redirectURI string, codeChallenge string, assertion string) *AcquireTokenAuthCodeParameters {
	p := &AcquireTokenAuthCodeParameters{
		commonParameters: createAcquireTokenCommonParameters(scopes),
		redirectURI:      redirectURI,
		codeChallenge:    codeChallenge,
		RequestType:      requests.AuthCodeClientAssertion,
		ClientAssertion:  assertion,
	}
	return p
}

func (p *AcquireTokenAuthCodeParameters) augmentAuthenticationParameters(authParams *msalbase.AuthParametersInternal) {
	p.commonParameters.augmentAuthenticationParameters(authParams)
	authParams.Redirecturi = p.redirectURI
	authParams.AuthorizationType = msalbase.AuthorizationTypeAuthCode
}

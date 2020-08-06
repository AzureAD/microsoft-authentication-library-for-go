// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "errors"

type ClientAssertion struct {
	ClientAssertionJWT string
	ClientCertificate  *ClientCertificate
}

func CreateClientAssertionFromJWT(jwt string) *ClientAssertion {
	return &ClientAssertion{ClientAssertionJWT: jwt, ClientCertificate: nil}
}

func CreateClientAssertionFromCertificate(thumbprint string, key []byte) *ClientAssertion {
	cert := CreateClientCertificate(thumbprint, key)
	assertion := &ClientAssertion{ClientCertificate: cert}
	return assertion
}

func CreateClientAssertionFromCertificateObject(cert *ClientCertificate) *ClientAssertion {
	assertion := &ClientAssertion{ClientCertificate: cert}
	return assertion
}

func (assertion *ClientAssertion) GetJWT(authParams *AuthParametersInternal) (string, error) {
	if assertion.ClientAssertionJWT == "" {
		if assertion.ClientCertificate == nil {
			return "", errors.New("no assertion or certificate found")
		}
		jwt, err := assertion.ClientCertificate.BuildJWT(
			authParams)
		if err != nil {
			return "", err
		}
		assertion.ClientAssertionJWT = jwt
		// Check if the assertion is built from an expired certificate
	} else if assertion.ClientCertificate != nil &&
		assertion.ClientCertificate.IsExpired() {
		jwt, err := assertion.ClientCertificate.BuildJWT(authParams)
		if err != nil {
			return "", err
		}
		assertion.ClientAssertionJWT = jwt
	}
	return assertion.ClientAssertionJWT, nil
}

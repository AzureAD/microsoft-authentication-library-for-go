// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "errors"

//ClientAssertion holds the assertion parameters required for token acquisition flows needing a client assertion.
//This can be either a JWT or certificate.
type ClientAssertion struct {
	ClientAssertionJWT string
	ClientCertificate  *ClientCertificate
}

//CreateClientAssertionFromJWT creates a ClientAssertion instance from a JWT
func CreateClientAssertionFromJWT(jwt string) *ClientAssertion {
	return &ClientAssertion{ClientAssertionJWT: jwt, ClientCertificate: nil}
}

//CreateClientAssertionFromCertificate creates a ClientAssertion instance from a certificate (thumbprint and private key)
func CreateClientAssertionFromCertificate(thumbprint string, key []byte) *ClientAssertion {
	cert := CreateClientCertificate(thumbprint, key)
	assertion := &ClientAssertion{ClientCertificate: cert}
	return assertion
}

//CreateClientAssertionFromCertificateObject creates a ClientAssertion instance from a ClientCertificate Instance
func CreateClientAssertionFromCertificateObject(cert *ClientCertificate) *ClientAssertion {
	assertion := &ClientAssertion{ClientCertificate: cert}
	return assertion
}

//GetJWT gets the assertion JWT from either the certificate or the JWT passed in
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

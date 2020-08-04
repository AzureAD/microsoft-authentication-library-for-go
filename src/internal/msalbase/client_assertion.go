// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

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

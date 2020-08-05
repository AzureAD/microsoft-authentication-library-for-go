// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type credentialType int

const (
	clientSecret credentialType = iota
	clientAssertion
)

//ClientCredential holds either a secret or assertion that can be used in confidential clients
type ClientCredential struct {
	clientSecret    string
	clientAssertion *msalbase.ClientAssertion
	credentialType  credentialType
}

//CreateClientCredentialFromSecret creates a ClientCredential instance from a client secret
func CreateClientCredentialFromSecret(secret string) *ClientCredential {
	return &ClientCredential{clientSecret: secret, clientAssertion: nil, credentialType: clientSecret}
}

//CreateClientCredentialFromCertificate creates a ClientCredential instance from a certificate
func CreateClientCredentialFromCertificate(thumbprint string, key []byte) *ClientCredential {
	return &ClientCredential{
		clientAssertion: msalbase.CreateClientAssertionFromCertificate(thumbprint, key),
		credentialType:  clientAssertion,
	}
}

//CreateClientCredentialFromAssertionJWT creates a ClientCredentialInstance from an assertion JWT
func CreateClientCredentialFromAssertionJWT(assertion string) *ClientCredential {
	return &ClientCredential{
		clientAssertion: msalbase.CreateClientAssertionFromJWT(assertion),
		credentialType:  clientAssertion,
	}
}

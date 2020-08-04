// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type credentialType int

const (
	clientSecret credentialType = iota
	clientAssertion
)

type ClientCredential struct {
	clientSecret    string
	clientAssertion *msalbase.ClientAssertion
	credentialType  credentialType
}

func CreateClientCredentialFromSecret(secret string) *ClientCredential {
	return &ClientCredential{clientSecret: secret, clientAssertion: nil, credentialType: clientSecret}
}

func CreateClientCredentialFromCertificate(thumbprint string, key []byte) *ClientCredential {
	return &ClientCredential{
		clientAssertion: msalbase.CreateClientAssertionFromCertificate(thumbprint, key),
		credentialType:  clientAssertion,
	}
}

func CreateClientCredentialFromAssertionJWT(assertion string) *ClientCredential {
	return &ClientCredential{
		clientAssertion: msalbase.CreateClientAssertionFromJWT(assertion),
		credentialType:  clientAssertion,
	}
}

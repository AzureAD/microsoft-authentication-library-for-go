// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type credentialType int

const (
	clientSecret credentialType = iota
	clientAssertion
)

type ClientCredentialInterfacer interface {
	GetCredentialType() msalbase.ClientCredentialType
	GetSecret() string
	GetAssertion() *msalbase.ClientAssertion
}

func CreateClientCredentialFromSecret(secret string) (ClientCredentialInterfacer, error) {
	return msalbase.CreateClientCredentialFromSecret(secret)
}

func CreateClientCredentialFromCertificate(thumbprint string, key []byte) (ClientCredentialInterfacer, error) {
	return msalbase.CreateClientCredentialFromCertificate(thumbprint, key)
}

func CreateClientCredentialFromAssertion(assertion string) (ClientCredentialInterfacer, error) {
	return msalbase.CreateClientCredentialFromAssertion(assertion)
}

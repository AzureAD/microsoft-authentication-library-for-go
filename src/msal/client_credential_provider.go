// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"

type credentialType int

const (
	clientSecret credentialType = iota
	clientAssertion
)

//ClientCredentialProvider is an interface representing a client secret/assertion.
// These are generated when you create your application on your Azure AD tenant.
//This is required to create a ConfidentialClientApplication instance.
type ClientCredentialProvider interface {
	GetCredentialType() msalbase.ClientCredentialType
	GetSecret() string
	GetAssertion() *msalbase.ClientAssertion
}

//CreateClientCredentialFromSecret returns a ClientCredentialProvider when given a client secret.
func CreateClientCredentialFromSecret(secret string) (ClientCredentialProvider, error) {
	return msalbase.CreateClientCredentialFromSecret(secret)
}

//CreateClientCredentialFromCertificate returns a ClientCredentialProvider when given a thumbprint and private key represnting the certificate.
func CreateClientCredentialFromCertificate(thumbprint string, key []byte) (ClientCredentialProvider, error) {
	return msalbase.CreateClientCredentialFromCertificate(thumbprint, key)
}

//CreateClientCredentialFromAssertion returns a ClientCredentialProvider when given an assertion JWT.
func CreateClientCredentialFromAssertion(assertion string) (ClientCredentialProvider, error) {
	return msalbase.CreateClientCredentialFromAssertion(assertion)
}

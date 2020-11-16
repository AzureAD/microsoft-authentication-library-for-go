// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "errors"

// ClientCredentialType refers to the type of credential used for confidential client flows.
type ClientCredentialType int

// Values for ClientCredentialType.
// TODO(jdoak): This looks suspect.
const (
	ClientCredentialSecret ClientCredentialType = iota
	ClientCredentialAssertion
)

// ClientCredential represents the credential used in confidential client flows.
type ClientCredential struct {
	clientSecret    string
	clientAssertion *ClientAssertion
	credentialType  ClientCredentialType
}

// CreateClientCredentialFromSecret creates a ClientCredential instance from a secret.
func CreateClientCredentialFromSecret(secret string) (ClientCredential, error) {
	if secret == "" {
		return ClientCredential{}, errors.New("client secret can't be blank")
	}
	return ClientCredential{clientSecret: secret, clientAssertion: nil, credentialType: ClientCredentialSecret}, nil
}

// CreateClientCredentialFromCertificate creates a ClientCredential instance from a certificate (thumbprint and private key).
func CreateClientCredentialFromCertificate(thumbprint string, key []byte) (ClientCredential, error) {
	if thumbprint == "" || len(key) == 0 {
		return ClientCredential{}, errors.New("thumbprint can't be blank or private key can't be empty")
	}
	return ClientCredential{
		clientAssertion: CreateClientAssertionFromCertificate(thumbprint, key),
		credentialType:  ClientCredentialAssertion,
	}, nil
}

// CreateClientCredentialFromCertificateObject creates a ClientCredential instance from a ClientCertificate instance.
func CreateClientCredentialFromCertificateObject(cert *ClientCertificate) ClientCredential {
	return ClientCredential{
		clientAssertion: CreateClientAssertionFromCertificateObject(cert),
		credentialType:  ClientCredentialAssertion,
	}
}

// CreateClientCredentialFromAssertion creates a ClientCredential instance from an assertion JWT.
func CreateClientCredentialFromAssertion(assertion string) (ClientCredential, error) {
	if assertion == "" {
		return ClientCredential{}, errors.New("assertion can't be blank")
	}
	return ClientCredential{
		clientAssertion: CreateClientAssertionFromJWT(assertion),
		credentialType:  ClientCredentialAssertion,
	}, nil
}

// GetCredentialType returns the type of the ClientCredential.
func (cred ClientCredential) GetCredentialType() ClientCredentialType {
	return cred.credentialType
}

// GetSecret returns the secret of ClientCredential instance.
func (cred ClientCredential) GetSecret() string {
	return cred.clientSecret
}

// GetAssertion returns the assertion of the ClientCredential instance.
func (cred ClientCredential) GetAssertion() *ClientAssertion {
	return cred.clientAssertion
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import "errors"

type ClientCredentialType int

const (
	ClientCredentialSecret ClientCredentialType = iota
	ClientCredentialAssertion
)

type ClientCredential struct {
	clientSecret    string
	clientAssertion *ClientAssertion
	credentialType  ClientCredentialType
}

func CreateClientCredentialFromSecret(secret string) (*ClientCredential, error) {
	if secret == "" {
		return nil, errors.New("client secret can't be blank")
	}
	return &ClientCredential{clientSecret: secret, clientAssertion: nil, credentialType: ClientCredentialSecret}, nil
}

func CreateClientCredentialFromCertificate(thumbprint string, key []byte) (*ClientCredential, error) {
	if thumbprint == "" || len(key) == 0 {
		return nil, errors.New("thumbprint can't be blank or private key can't be empty")
	}
	return &ClientCredential{
		clientAssertion: CreateClientAssertionFromCertificate(thumbprint, key),
		credentialType:  ClientCredentialAssertion,
	}, nil
}

func CreateClientCredentialFromCertificateObject(cert *ClientCertificate) *ClientCredential {
	return &ClientCredential{
		clientAssertion: CreateClientAssertionFromCertificateObject(cert),
		credentialType:  ClientCredentialAssertion,
	}
}

func CreateClientCredentialFromAssertion(assertion string) (*ClientCredential, error) {
	if assertion == "" {
		return nil, errors.New("assertion can't be blank")
	}
	return &ClientCredential{
		clientAssertion: CreateClientAssertionFromJWT(assertion),
		credentialType:  ClientCredentialAssertion,
	}, nil
}

func (cred *ClientCredential) GetCredentialType() ClientCredentialType {
	return cred.credentialType
}

func (cred *ClientCredential) GetSecret() string {
	return cred.clientSecret
}

func (cred *ClientCredential) GetAssertion() *ClientAssertion {
	return cred.clientAssertion
}

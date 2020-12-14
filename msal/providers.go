// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//AccountProvider is an interface representing an account that is returned to users.
//This can help with accessing the cache for tokens.
type AccountProvider interface {
	GetUsername() string
	GetHomeAccountID() string
	GetEnvironment() string
}

// AuthenticationResultProvider contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication.
type AuthenticationResultProvider interface {
	GetAccessToken() string
}

// DeviceCodeResultProvider is an interface for DeviceCodeResult that can be returned to users.
// You can use these functions to show the user different parameters of the device code result.
type DeviceCodeResultProvider interface {
	GetMessage() string
	String() string
	GetUserCode() string
	GetDeviceCode() string
	GetVerificationURL() string
	GetExpiresOn() time.Time
	GetInterval() int
}

// ClientCredentialProvider is an interface representing a client credential.
// This is required to create a ConfidentialClientApplication instance.
type ClientCredentialProvider interface {
	GetCredentialType() msalbase.ClientCredentialType
	GetSecret() string
	GetAssertion() *msalbase.ClientAssertion
}

// CreateClientCredentialFromSecret returns a ClientCredentialProvider when given a client secret.
func CreateClientCredentialFromSecret(secret string) (ClientCredentialProvider, error) {
	return msalbase.CreateClientCredentialFromSecret(secret)
}

// CreateClientCredentialFromCertificate returns a ClientCredentialProvider when given a thumbprint and private key representing the certificate.
// Requires hex encoded X.509 SHA-1 thumbprint of the certificiate, and the PEM encoded private key
// (string should contain -----BEGIN PRIVATE KEY----- ... -----END PRIVATE KEY----- )
func CreateClientCredentialFromCertificate(thumbprint string, key []byte) (ClientCredentialProvider, error) {
	return msalbase.CreateClientCredentialFromCertificate(thumbprint, key)
}

// CreateClientCredentialFromAssertion returns a ClientCredentialProvider when given an assertion JWT.
// Assertion should be of type urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
func CreateClientCredentialFromAssertion(assertion string) (ClientCredentialProvider, error) {
	return msalbase.CreateClientCredentialFromAssertion(assertion)
}

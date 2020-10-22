// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

// AuthenticationResultProvider contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication.
type AuthenticationResultProvider interface {
	GetAccessToken() string
}

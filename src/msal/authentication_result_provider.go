// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

// AuthenticationResultProvider contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication.
type AuthenticationResultProvider interface {
	GetAccessToken() string
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

// AuthenticationResultInterfacer contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication.
type AuthenticationResultInterfacer interface {
	GetAccessToken() string
}

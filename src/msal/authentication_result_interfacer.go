// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

// AuthenticationResultInterfacer contains the results of one token acquisition operation in PublicClientApplication
// or ConfidentialClientApplication. For details see https://aka.ms/msal-net-authenticationresult
type AuthenticationResultInterfacer interface {
	GetAccessToken() string
}

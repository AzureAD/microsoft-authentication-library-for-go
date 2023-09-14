// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package broker

import "github.com/AzureAD/microsoft-authentication-library-for-go/internal/account"

// AuthParams represents the parameters used for authorization for token acquisition.
type AuthParams struct {
	// Account is used only for silent auth
	Account account.Account

	// Authority for the token request e.g. https://login.microsoftonline.com/tenant
	// TODO: does AuthParams.WithTenantID update canonical URL?
	Authority string

	Claims string

	ClientID string

	CorrelationID string

	// TODO
	ParentWindow uintptr

	RedirectURI string

	Scopes []string

	Title string

	Username, Password string
}

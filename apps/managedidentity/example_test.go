// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity_test

import (
	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func ExampleNew() {
	// System assigned Client
	miSystemassignedClient, err := mi.New(mi.SystemAssigned())
	if err != nil {
		// TODO: Handle error
	}
	_ = miSystemassignedClient

	// User assigned Client
	clientId := "ClientId" // TODO: replace with your Managed Identity Id

	miClientIdAssignedClient, err := mi.New(mi.UserAssignedClientID(clientId), mi.WithClientCapabilities([]string{"cp1"}))
	if err != nil {
		// TODO: Handle error
	}
	_ = miClientIdAssignedClient
}

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity_test

import (
	"context"
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

var miSystemassignedClient mi.Client
var err error

func ExampleNew() {
	// System assigned Client
	miSystemassignedClient, err = mi.New(mi.SystemAssigned())
	if err != nil {
		// TODO: Handle error
	}
	_ = miSystemassignedClient

	// User assigned Client
	clientId := "ClientId" // TODO: replace the correct Client id

	miClientIdAssignedClient, err := mi.New(mi.UserAssignedClientID(clientId))
	if err != nil {
		// TODO: Handle error
	}
	_ = miClientIdAssignedClient

	// Output: -
}

func ExampleClient_AcquireToken() {
	miClient, err := mi.New(mi.SystemAssigned())
	if err != nil {
		// TODO: Handle error
	}
	token, err := miClient.AcquireToken(context.Background(), "resouce")
	if err != nil {
		// TODO: Handle error
	}
	fmt.Println("Token expires at:", token.ExpiresOn)

	// Output: Token expires at: <datetime>

}

func ExampleGetSource() {
	source, err := mi.GetSource()
	if err != nil {
		// TODO: Handle error
	}
	print("source is :", source)

	// Output: source is : <source>
}

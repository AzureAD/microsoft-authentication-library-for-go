// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity_test

import (
	"context"
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func ExampleNew() {
	miClient, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println("Error while making client", err)
	}
	token, err := miClient.AcquireToken(context.Background(), "resouce")
	if err != nil {
		fmt.Println("Error while fetching token", err)
	}
	fmt.Println("Token expires at:", token.ExpiresOn)
	// Output:
}

func ExampleClient_AcquireToken() {
	miClient, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println("Error while making client", err)
	}
	token, err := miClient.AcquireToken(context.Background(), "resouce")
	if err != nil {
		fmt.Println("Error while fetching token", err)
	}
	fmt.Println("Token expires at:", token.ExpiresOn)
	// Output:

}

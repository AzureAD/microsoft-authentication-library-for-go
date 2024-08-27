package main

import (
	"context"
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func RunManagedIdentity() {
	// customHttpClient := &http.Client{}

	miSystemAssigned, error := mi.New(mi.SystemAssigned())
	if error != nil {
		fmt.Println(error)
	}

	// miClientIdAssigned, error := mi.New(mi.ClientID("951d3571-c442-42e0-9efd-e1d7e1a21030"),
	// 	mi.WithHTTPClient(customHttpClient))
	// if error != nil {
	// 	fmt.Println(error)
	// }

	// miResourceIdAssigned, error := mi.New(mi.ResourceID("resource id 123"))
	// if error != nil {
	// 	fmt.Println(error)
	// }

	// miObjectIdAssigned, error := mi.New(mi.ObjectID("object id 123"))
	// if error != nil {
	// 	fmt.Println(error)
	// }

	miSystemAssigned.AcquireToken(context.Background(), "https://management.azure.com/")
	// miClientIdAssigned.AcquireToken(context.Background(), "resource")
	// miResourceIdAssigned.AcquireToken(context.Background(), "resource", mi.WithClaims("claim"))
	// miObjectIdAssigned.AcquireToken(context.Background(), "resource")
}

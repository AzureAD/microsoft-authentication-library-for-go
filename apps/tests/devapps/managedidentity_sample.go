package main

import (
	"context"
	"fmt"
	"net/http"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func RunManagedIdentity() {
	customHttpClient := &http.Client{}

	miSystemAssigned, error := mi.New(mi.SystemAssigned())
	if error != nil {
		fmt.Println(error)
	}

	miClientIdAssigned, error := mi.New(mi.ClientID("client id 123"), mi.WithHTTPClient(customHttpClient))
	if error != nil {
		fmt.Println(error)
	}

	miResourceIdAssigned, error := mi.New(mi.ResourceID("resource id 123"))
	if error != nil {
		fmt.Println(error)
	}

	miObjectIdAssigned, error := mi.New(mi.ObjectID("object id 123"))
	if error != nil {
		fmt.Println(error)
	}

	miSystemAssigned.AcquireToken(context.Background(), "resource", mi.WithClaims("claim"))
	miClientIdAssigned.AcquireToken(context.Background(), "resource")
	miResourceIdAssigned.AcquireToken(context.Background(), "resource", mi.WithClaims("claim"))
	miObjectIdAssigned.AcquireToken(context.Background(), "resource")
}

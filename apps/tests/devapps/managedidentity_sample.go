package main

import (
	"context"
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func RunManagedIdentity() {
	miSystemAssigned, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println(err)
	}
	miSystemAssigned.AcquireToken(context.Background(), "https://management.azure.com/")

}

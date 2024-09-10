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
	temp, err := miSystemAssigned.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		println(err.Error())
	}
	fmt.Println("token : ", temp.AccessToken)
}

package main

import (
	"context"
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func runIMDSSystemAssigned() {

	miSystemAssigned, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println(err)
	}
	result, err := miSystemAssigned.AcquireToken(context.Background(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
	fmt.Println("token source : ", result.Metadata.TokenSource)

	result1, err1 := miSystemAssigned.AcquireToken(context.Background(), "https://management.azure.com")
	if err1 != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result1.ExpiresOn)
	fmt.Println("token source : ", result1.Metadata.TokenSource)

}

func runIMDSUserAssigned() {
	miUserAssigned, err := mi.New(mi.UserAssignedClientID("YOUR_CLIENT_ID"))
	if err != nil {
		fmt.Println(err)
	}
	result, err := miUserAssigned.AcquireToken(context.Background(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("token expire at : ", result.ExpiresOn)
	fmt.Println("token source : ", result.Metadata.TokenSource)

	result1, err1 := miUserAssigned.AcquireToken(context.Background(), "https://management.azure.com")
	if err1 != nil {
		fmt.Println(err)
	}

	fmt.Println("token expire at : ", result1.ExpiresOn)
	fmt.Println("token source : ", result1.Metadata.TokenSource)
}

func main() {
	exampleType := "2"

	if exampleType == "1" {
		runIMDSSystemAssigned()
	} else if exampleType == "2" {
		runIMDSUserAssigned()
	}
}

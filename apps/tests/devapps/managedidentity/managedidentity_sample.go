package main

import (
	"context"
	"fmt"
	"log"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func runIMDSSystemAssigned() {

	miSystemAssigned, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println(err)
	}
	result, err := miSystemAssigned.AcquireToken(context.TODO(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
	fmt.Println("token source : ", result.Metadata.TokenSource)
	miSystemAssignedCache, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}
	result1, err1 := miSystemAssignedCache.AcquireToken(context.Background(), "https://management.azure.com")
	if err1 != nil {
		log.Fatal(err)
	}
	fmt.Println("token expire at : ", result1.ExpiresOn)
	fmt.Println("token source : ", result1.Metadata.TokenSource)

}

func runIMDSUserAssigned() {
	miUserAssigned, err := mi.New(mi.UserAssignedClientID("YOUR_CLIENT_ID"))
	if err != nil {
		log.Fatal(err)
	}
	result, err := miUserAssigned.AcquireToken(context.TODO(), "https://management.azure.com")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("token expire at : ", result.ExpiresOn)
}

func main() {
	exampleType := "1"

	if exampleType == "1" {
		runIMDSSystemAssigned()
	} else if exampleType == "2" {
		runIMDSUserAssigned()
	}
}

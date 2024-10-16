package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func acquireToken(identity mi.ID) {
	tokenProvider, err := mi.New(identity)
	if err != nil {
		fmt.Println(err)
		return
	}
	result, err := tokenProvider.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func setEnvironmentVariablesIfRequired() {
	os.Setenv("IDENTITY_ENDPOINT", "identityEndpointVar")
	os.Setenv("IMDS_ENDPOINT", "imdsEnvVar")
}

func promptForLocalTest() {
	fmt.Println("Do you want to run a local test? (yes/no):")
	var localTestInput string
	for {
		fmt.Scanln(&localTestInput)
		localTestInput = strings.ToLower(localTestInput)
		if localTestInput == "yes" {
			setEnvironmentVariablesIfRequired()
			break
		} else if localTestInput == "no" {
			break
		} else {
			fmt.Println("Invalid input. Please enter 'yes' or 'no'.")
		}
	}
}

func promptForID(idType string) string {
	fmt.Printf("Enter the %s: ", idType)
	var id string
	fmt.Scanln(&id)
	return id
}

func main() {
	var exampleType string
	fmt.Println("Enter the example type (1-8):")
	fmt.Scanln(&exampleType)

	var identity mi.ID
	switch exampleType {
	case "1":
		identity = mi.SystemAssigned()
	case "2":
		clientID := promptForID("Client ID")
		identity = mi.UserAssignedClientID(clientID)
	case "3":
		objectID := promptForID("Object ID")
		identity = mi.UserAssignedObjectID(objectID)
	case "4":
		resourceID := promptForID("Resource ID")
		identity = mi.UserAssignedResourceID(resourceID)
	case "5":
		promptForLocalTest()
		identity = mi.SystemAssigned()
	case "6":
		promptForLocalTest()
		identity = mi.UserAssignedClientID("This should fail")
	case "7":
		promptForLocalTest()
		identity = mi.UserAssignedObjectID("This should fail")
	case "8":
		promptForLocalTest()
		identity = mi.UserAssignedResourceID("This should fail")
	default:
		fmt.Println("Invalid example type")
		return
	}

	acquireToken(identity)
}

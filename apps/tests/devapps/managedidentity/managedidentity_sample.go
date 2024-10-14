package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

var isLocalTest = false

func runIMDSSystemAssigned() {
	miSystemAssigned, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println(err)
	}
	result, err := miSystemAssigned.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func runIMDSUserAssignedClientID() {
	miUserAssigned, err := mi.New(mi.UserAssignedClientID("YOUR_MANAGED_IDENTITY_CLIENT_ID"))
	if err != nil {
		fmt.Println(err)
	}
	result, err := miUserAssigned.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func runIMDSUserAssignedObjectID() {
	miUserAssigned, err := mi.New(mi.UserAssignedObjectID("YOUR_MANAGED_IDENTITY_CLIENT_ID"))
	if err != nil {
		fmt.Println(err)
	}
	result, err := miUserAssigned.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func runIMDSUserAssignedResourceID() {
	miUserAssigned, err := mi.New(mi.UserAssignedResourceID("YOUR_MANAGED_IDENTITY_CLIENT_ID"))
	if err != nil {
		fmt.Println(err)
	}
	result, err := miUserAssigned.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func runAzureArcSystemAssigned() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)

	miAzureArc, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Println(err)
	}
	result, err := miAzureArc.AcquireToken(context.Background(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func runAzureArcUserAssignedClientID() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)
	miAzureArc, err := mi.New(mi.UserAssignedClientID("This should fail"))
	if err != nil {
		fmt.Println(err)
	}

	_, err = miAzureArc.AcquireToken(context.Background(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}
}

func runAzureArcUserAssignedObjectID() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)

	miAzureArc, err := mi.New(mi.UserAssignedObjectID("This should fail"))
	if err != nil {
		fmt.Println(err)
	}

	_, err = miAzureArc.AcquireToken(context.Background(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}
}

func runAzureArcUserAssignedResourceID() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)

	miAzureArc, err := mi.New(mi.UserAssignedResourceID("This should fail"))
	if err != nil {
		fmt.Println(err)
	}

	_, err = miAzureArc.AcquireToken(context.Background(), "https://management.azure.com")
	if err != nil {
		fmt.Println(err)
	}
}

func setEnvironmentVariablesIfRequired(source mi.Source) {
	if isLocalTest {
		switch source {
		case mi.AzureArc:
			os.Setenv(mi.IdentityEndpointEnvVar, "identityEndpointVar")
			os.Setenv(mi.ArcIMDSEnvVar, "imdsEnvVar")
		}
	}
}

func main() {
	var localTestInput string
	for {
		fmt.Println("Do you want to run a local test? (yes/no):")
		fmt.Scanln(&localTestInput)
		localTestInput = strings.ToLower(localTestInput)
		if localTestInput == "yes" {
			isLocalTest = true
			break
		} else if localTestInput == "no" {
			isLocalTest = false
			break
		} else {
			fmt.Println("Invalid input. Please enter 'yes' or 'no'.")
		}
	}

	var exampleType string
	fmt.Println("Enter the example type (1-8):")
	fmt.Scanln(&exampleType)

	switch exampleType {
	case "1":
		runIMDSSystemAssigned()
	case "2":
		runIMDSUserAssignedClientID()
	case "3":
		runIMDSUserAssignedObjectID()
	case "4":
		runIMDSUserAssignedResourceID()
	case "5":
		runAzureArcSystemAssigned()
	case "6":
		runAzureArcUserAssignedClientID()
	case "7":
		runAzureArcUserAssignedObjectID()
	case "8":
		runAzureArcUserAssignedResourceID()
	default:
		fmt.Println("Invalid example type")
	}
}

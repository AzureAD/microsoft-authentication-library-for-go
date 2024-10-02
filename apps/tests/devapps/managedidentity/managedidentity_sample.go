package main

import (
	"context"
	"fmt"
	"os"

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
	result, err := miAzureArc.AcquireToken(context.Background(), "https://management.azure.com/")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token expire at : ", result.ExpiresOn)
}

func runAzureArcUserAssignedClientID() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)

	_, err := mi.New(mi.UserAssignedClientID("This should fail"))
	if err != nil {
		fmt.Println(err)
	}
}

func runAzureArcUserAssignedObjectID() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)

	_, err := mi.New(mi.UserAssignedObjectID("This should fail"))
	if err != nil {
		fmt.Println(err)
	}
}

func runAzureArcUserAssignedResourceID() {
	setEnvironmentVariablesIfRequired(mi.AzureArc)

	_, err := mi.New(mi.UserAssignedResourceID("This should fail"))
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
	exampleType := "6"

	if exampleType == "1" {
		runIMDSSystemAssigned()
	} else if exampleType == "2" {
		runIMDSUserAssignedClientID()
	} else if exampleType == "3" {
		runIMDSUserAssignedObjectID()
	} else if exampleType == "4" {
		runIMDSUserAssignedResourceID()
	} else if exampleType == "5" {
		runAzureArcSystemAssigned()
	} else if exampleType == "6" {
		runAzureArcUserAssignedClientID()
	} else if exampleType == "7" {
		runAzureArcUserAssignedObjectID()
	} else if exampleType == "8" {
		runAzureArcUserAssignedResourceID()
	}
}

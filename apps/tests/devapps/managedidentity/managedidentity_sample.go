package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

func getSecretFromAzureVault() {
	keyVaultUri := "your-key-vault-uri"
	secretName := "your-secret-name"

	// Comment this and uncomment the following lines to test different scenarios
	miClient, err := mi.New(mi.SystemAssigned())
	// miClient, err := mi.New(mi.UserAssignedClientID("my-client-id"))
	// miClient, err := mi.New(mi.UserAssignedObjectID("my-object-id"))
	// miClient, err := mi.New(mi.UserAssignedResourceID("my-resource-id"))
	if err != nil {
		log.Fatalf("failed to create a new managed identity client: %v", err)
		return
	}

	accessToken, err := miClient.AcquireToken(context.Background(), "https://vault.azure.net")
	if err != nil {
		log.Fatalf("failed to acquire token: %v", err)
		return
	}

	println(fmt.Sprintf("Access token: %s", accessToken.AccessToken))

	// Create http request using access token
	url := fmt.Sprintf("%ssecrets/%s?api-version=7.2", keyVaultUri, secretName)

	// Create a new HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	// Set the authorization header
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken.AccessToken))

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	// Combine all received buffer streams into one buffer, and then into a string
	var parsedData map[string]interface{}
	if err := json.Unmarshal(body, &parsedData); err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	// Print the response body
	println(fmt.Sprintf("The secret, %s, has a value of: %s", secretName, string(body)))
}

func main() {
	var exampleType string
	fmt.Println("Enter the example type (1-9):")
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
	case "9":
		getSecretFromAzureVault()
	default:
		fmt.Println("Invalid example type")
		return
	}

	acquireToken(identity)
}

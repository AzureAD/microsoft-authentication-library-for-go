package main

import (
	"context"
	"fmt"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"log"
	"os"
	"strconv"
)

func acquirePublicTokenWithoutInstanceDiscovery() {
	config := CreateConfig("config.json")
	fmt.Printf("\nusing authority %s\n", config.Authority)

	instanceDiscovery, err := strconv.ParseBool(config.InstanceDiscovery)
	if err != nil {
		fmt.Println("Failed to parse boolean from config file: %w", err)
	}
	//Get public client token
	publicClientApp, err := public.New(config.ClientID, public.WithAuthority(config.Authority), public.WithInstanceDiscovery(instanceDiscovery))

	if err != nil {
		fmt.Println("could not create app: %w", err)
	}

	result, err := publicClientApp.AcquireTokenInteractive(context.Background(), config.Scopes)

	if err != nil {
		fmt.Println("could not get token: %w", err)
	}

	fmt.Printf("access token %s\n\n", result.AccessToken)

	//Try to get public client token from cache

	fmt.Println("\nTrying to get token from cache")

	var userAccount public.Account
	var accounts = publicClientApp.Accounts()

	if len(accounts) > 0 {

		fmt.Println("\nCached account found, searching for cached token")
		userAccount = accounts[0]
		result, err := publicClientApp.AcquireTokenSilent(context.Background(), config.Scopes, public.WithSilentAccount(userAccount))
		if err != nil {
			fmt.Println("could not get token: %w", err)
		}
		fmt.Printf("cached access token %s\n\n", result.AccessToken)
	} else {
		fmt.Println("\nNo cached account found")
	}
}

func acquireConfidentialTokenWithoutInstanceDiscovery() {

	config := CreateConfig("confidential_config.json")

	pemData, err := os.ReadFile(config.PemData)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Enter certificate password if applicable")
	var password string
	_, err = fmt.Scanln(&password)
	if err != nil {
		log.Fatal(err)
	}

	certs, privateKey, err := confidential.CertFromPEM(pemData, password)
	if err != nil {
		log.Fatal(err)
	}

	cred := confidential.NewCredFromCert(certs[0], privateKey)

	if err != nil {
		fmt.Println("could not create a cred from a secret: %w", err)
	}

	instanceDiscovery, err := strconv.ParseBool(config.InstanceDiscovery)
	if err != nil {
		fmt.Println("Failed to parse boolean from config file: %w", err)
	}

	fmt.Printf("\nusing authority %s, validate authority = %t\n", config.Authority, instanceDiscovery)

	confidentialClientApp, err := confidential.New(config.ClientID, cred, confidential.WithAuthority(config.Authority), confidential.WithInstanceDiscovery(instanceDiscovery))

	if err != nil {
		fmt.Println("could not create app: %w", err)
	}

	result, err := confidentialClientApp.AcquireTokenByCredential(context.Background(), config.Scopes)

	if err != nil {
		fmt.Println("could not get token: %w", err)
	}

	fmt.Printf("access token %s\n\n", result.AccessToken)

}

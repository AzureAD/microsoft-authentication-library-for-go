// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"

	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

func tryClientSecretFlow(confidentialClientApp *msal.ConfidentialClientApplication) {
	result, err := confidentialClientApp.AcquireTokenByClientCredential(context.Background(), confidentialConfig.Scopes)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Println("Access token is: " + accessToken)
}

func acquireTokenClientSecret() {
	secret, err := msal.CreateClientCredentialFromSecret(confidentialConfig.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}
	options := msal.DefaultConfidentialClientApplicationOptions()
	options.Accessor = cacheAccessor
	options.Authority = confidentialConfig.Authority
	confidentialClientApp, err := msal.NewConfidentialClientApplication(confidentialConfig.ClientID, secret, &options)
	if err != nil {
		log.Fatal(err)
	}
	result, err := confidentialClientApp.AcquireTokenSilent(context.Background(), confidentialConfig.Scopes, nil)
	if err != nil {
		log.Println(err)
		tryClientSecretFlow(confidentialClientApp)
	} else {
		accessToken := result.GetAccessToken()
		log.Println("Access token is: " + accessToken)
	}

}

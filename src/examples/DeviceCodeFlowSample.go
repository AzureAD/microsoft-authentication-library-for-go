// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"fmt"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	log "github.com/sirupsen/logrus"
)

func acquireTokenDeviceCode() {
	config := CreateConfig("config.json")
	// Creating the Public Client Application
	fmt.Println(config.GetClientID(), config.GetAuthority())
	pcaParams := createPCAParams(config.GetClientID(), config.GetAuthority())
	publicClientApp, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(config.GetScopes())
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(config.GetScopes())
	result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

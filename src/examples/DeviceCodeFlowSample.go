// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"fmt"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	log "github.com/sirupsen/logrus"
)

// CLIENTID is a UUID issued by the authorization server for your application
const CLIENTID string = "649e183b-9097-4a61-8222-10be1ab5c7c3"

// AUTHORITY is a URL that defines token authority
const AUTHORITY string = "https://login.microsoftonline.com/f86c8166-c7df-412e-b770-884135fdedf5"

//SCOPES are requested to access a protected API
var SCOPES []string = []string{"user.read"}

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

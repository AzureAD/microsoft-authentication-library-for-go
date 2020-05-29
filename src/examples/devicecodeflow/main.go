// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	log "github.com/sirupsen/logrus"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
)

// CLIENTID is a UUID issued by the authorization server for your application
const CLIENTID string = "0615b6ca-88d4-4884-8729-b178178f7c27"

// AUTHORITY is a URL that defines token authority
const AUTHORITY string = "https://login.microsoftonline.com/organizations"

//SCOPES are requested to access a protected API
var SCOPES []string = []string{"user.read"}

//createPCAParams is used to instantiate the parameters to create the Public Client Application
func createPCAParams() *msalgo.PublicClientApplicationParameters {
	pcaParams := msalgo.CreatePublicClientApplicationParameters(CLIENTID)
	pcaParams.SetAadAuthority(AUTHORITY)
	return pcaParams
}

func acquireTokenDeviceCode() {
	// Creating the Public Client Application
	pcaParams := createPCAParams()
	publicClientApp, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}

	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(SCOPES)
	result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

func main() {
	acquireTokenDeviceCode()
}

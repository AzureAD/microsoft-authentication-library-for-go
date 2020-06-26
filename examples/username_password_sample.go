// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

func acquireByUsernamePasswordPublic() {
	config := createConfig("config.json")
	// Creating the Public Client Application
	pcaParams := createPCAParams(config.ClientID, config.Authority)
	pca, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	userNameParams := msalgo.CreateAcquireTokenUsernamePasswordParameters(config.Scopes, config.Username, config.Password)
	result, err := pca.AcquireTokenByUsernamePassword(userNameParams)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

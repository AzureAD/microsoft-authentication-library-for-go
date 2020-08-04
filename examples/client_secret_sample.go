// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	log "github.com/sirupsen/logrus"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
)

func tryClientSecretFlow(confidentialClientApp *msalgo.ConfidentialClientApplication) {
	clientSecretParams := msalgo.CreateAcquireTokenClientSecretParameters(confidentialConfig.Scopes)
	result, err := confidentialClientApp.AcquireTokenByClientSecret(clientSecretParams)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

func acquireTokenClientSecret() {
	secret := msalgo.CreateClientCredentialFromSecret(confidentialConfig.ClientSecret)
	confidentialClientApp := msalgo.CreateConfidentialClientApplication(
		confidentialConfig.ClientID, confidentialConfig.Authority, secret)
	confidentialClientApp.SetCacheAccessor(cacheAccessor)
	silentParams := msalgo.CreateAcquireTokenSilentParameters(confidentialConfig.Scopes)
	result, err := confidentialClientApp.AcquireTokenSilent(silentParams)
	if err != nil {
		log.Info(err)
		tryClientSecretFlow(confidentialClientApp)
	} else {
		accessToken := result.GetAccessToken()
		log.Info("Access token is: " + accessToken)
	}

}

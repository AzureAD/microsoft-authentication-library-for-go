// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"fmt"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
	log "github.com/sirupsen/logrus"
)

func tryUsernamePasswordFlow(publicClientApp *msal.PublicClientApplication) {
	userNameParams := msal.CreateAcquireTokenUsernamePasswordParameters(config.Scopes, config.Username, config.Password)
	result, err := publicClientApp.AcquireTokenByUsernamePassword(userNameParams)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

func acquireByUsernamePasswordPublic() {
	config := createConfig("config.json")
	// Creating the Public Client Application
	publicClientApp, err := msal.CreatePublicClientApplication(config.ClientID, config.Authority)
	if err != nil {
		log.Fatal(err)
	}
	publicClientApp.SetCacheAccessor(cacheAccessor)
	var userAccount msal.AccountProvider
	accounts := publicClientApp.GetAccounts()
	for _, account := range accounts {
		if account.GetUsername() == config.Username {
			userAccount = account
		}
	}
	if userAccount == nil {
		log.Info("No valid account found")
		tryUsernamePasswordFlow(publicClientApp)
	} else {
		silentParams := msal.CreateAcquireTokenSilentParametersWithAccount(config.Scopes, userAccount)
		result, err := publicClientApp.AcquireTokenSilent(silentParams)
		if err != nil {
			log.Info(err)
			tryUsernamePasswordFlow(publicClientApp)
		} else {
			fmt.Println("Access token is " + result.GetAccessToken())
		}
	}
}

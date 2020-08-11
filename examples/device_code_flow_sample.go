// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"time"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

func deviceCodeCallback(deviceCodeResult msalgo.DeviceCodeResultProvider) {
	log.Infof(deviceCodeResult.GetMessage())
}

func tryDeviceCodeFlow(publicClientApp *msalgo.PublicClientApplication) {
	cancelTimeout := 100 //Change this for cancel timeout
	cancelCtx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(cancelTimeout)*time.Second)
	defer cancelFunc()
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(cancelCtx, config.Scopes, deviceCodeCallback)
	resultChannel := make(chan msalgo.AuthenticationResultProvider)
	errChannel := make(chan error)
	go func() {
		result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams)
		errChannel <- err
		resultChannel <- result
	}()
	err = <-errChannel
	if err != nil {
		log.Fatal(err)
	}
	result := <-resultChannel
	fmt.Println("Access token is " + result.GetAccessToken())
}

func acquireTokenDeviceCode() {
	config := createConfig("config.json")
	publicClientApp, err := msalgo.CreatePublicClientApplication(config.ClientID, config.Authority)
	if err != nil {
		log.Fatal(err)
	}
	publicClientApp.SetCacheAccessor(cacheAccessor)
	var userAccount msalgo.AccountProvider
	accounts := publicClientApp.GetAccounts()
	for _, account := range accounts {
		if account.GetUsername() == config.Username {
			userAccount = account
		}
	}
	if userAccount == nil {
		log.Info("No valid account found")
		tryDeviceCodeFlow(publicClientApp)
	} else {
		silentParams := msalgo.CreateAcquireTokenSilentParametersWithAccount(config.Scopes, userAccount)
		result, err := publicClientApp.AcquireTokenSilent(silentParams)
		if err != nil {
			log.Info(err)
			tryDeviceCodeFlow(publicClientApp)
		} else {
			fmt.Println("Access token is " + result.GetAccessToken())
		}
	}
}

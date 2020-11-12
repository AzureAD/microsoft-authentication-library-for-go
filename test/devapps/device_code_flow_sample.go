// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
	log "github.com/sirupsen/logrus"
)

func deviceCodeCallback(deviceCodeResult msal.DeviceCodeResultProvider) {
	log.Infof(deviceCodeResult.GetMessage())
}

func acquireTokenDeviceCode() {
	config := createConfig("config.json")
	// create a PublicClientApplication with a  custom cache accessor
	options := msal.DefaultPublicClientApplicationOptions()
	options.Accessor = cacheAccessor
	options.Authority = config.Authority
	publicClientApp, err := msal.NewPublicClientApplication(config.ClientID, &options)
	if err != nil {
		panic(err)
	}

	// look in the cache to see if the account to use has been cached
	var userAccount msalbase.Account
	accounts := publicClientApp.Accounts()
	for _, account := range accounts {
		if account.PreferredUsername == config.Username {
			userAccount = account
		}
	}
	// found a cached account, now see if an applicable token has been cached
	// NOTE: this API conflates error states, i.e. err is non-nil if an applicable token isn't
	//       cached or if something goes wrong (making the HTTP request, unmarshalling, etc).
	result, err := publicClientApp.AcquireTokenSilent(
		context.Background(),
		config.Scopes, 
		&msal.AcquireTokenSilentOptions{
			Account: userAccount,
		},
	)
	if err != nil {
		// either there's no applicable token in the cache or something failed
		panic(err)
	}
	// either there was no cached account/token or the call to AcquireTokenSilent() failed
	// make a new request to AAD
	cancelTimeout := 100 * time.Second //Change this for cancel timeout
	cancelCtx, cancelFunc := context.WithTimeout(context.Background(), cancelTimeout)
	defer cancelFunc()
	result, err = publicClientApp.AcquireTokenByDeviceCode(cancelCtx, config.Scopes, deviceCodeCallback, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Access token is " + result.AccessToken)
}

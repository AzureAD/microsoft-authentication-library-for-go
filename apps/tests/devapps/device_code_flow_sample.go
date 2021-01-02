// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

func acquireTokenDeviceCode() {
	config := CreateConfig("config.json")

	app, err := public.New(config.ClientID, public.Cache(cacheAccessor), public.Authority(config.Authority))
	if err != nil {
		panic(err)
	}

	// look in the cache to see if the account to use has been cached
	var userAccount msalbase.Account
	accounts := app.Accounts()
	for _, account := range accounts {
		if account.PreferredUsername == config.Username {
			userAccount = account
		}
	}
	// found a cached account, now see if an applicable token has been cached
	// NOTE: this API conflates error states, i.e. err is non-nil if an applicable token isn't
	//       cached or if something goes wrong (making the HTTP request, unmarshalling, etc).
	authResult, err := app.AcquireTokenSilent(context.Background(), config.Scopes, public.SilentAccount(userAccount))
	if err != nil {
		// either there was no cached account/token or the call to AcquireTokenSilent() failed
		// make a new request to AAD
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		devCode, err := app.AcquireTokenByDeviceCode(ctx, config.Scopes)
		cancel()
		if err != nil {
			panic(err)
		}
		fmt.Printf("Device Code is: %s\n", devCode.Result.GetMessage())
		result, err := devCode.AuthenticationResult()
		if err != nil {
			panic(fmt.Sprintf("got error while waiting for user to input the device code: %s", err))
		}
		fmt.Println("Access token is " + result.AccessToken)
		return
	}
	fmt.Println("Access token is " + authResult.AccessToken)
}

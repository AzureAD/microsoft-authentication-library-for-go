// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

func acquireTokenDeviceCode() {
	config := CreateConfig("config.json")

	app, err := public.New(config.ClientID, public.WithCache(cacheAccessor), public.WithAuthority(config.Authority))
	if err != nil {
		panic(err)
	}

	// look in the cache to see if the account to use has been cached
	var userAccount public.Account
	accounts, err := app.Accounts(context.Background())
	if err != nil {
		panic("failed to read the cache")
	}
	for _, account := range accounts {
		if account.PreferredUsername == config.Username {
			userAccount = account
		}
	}
	// found a cached account, now see if an applicable token has been cached
	// NOTE: this API conflates error states, i.e. err is non-nil if an applicable token isn't
	//       cached or if something goes wrong (making the HTTP request, unmarshalling, etc).
	authResult, err := app.AcquireTokenSilent(context.Background(), config.Scopes, public.WithSilentAccount(userAccount))
	if err != nil {
		// either there was no cached account/token or the call to AcquireTokenSilent() failed
		// make a new request to AAD
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		devCode, err := app.AcquireTokenByDeviceCode(ctx, config.Scopes)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Device Code is: %s\n", devCode.Result.Message)
		result, err := devCode.AuthenticationResult(ctx)
		if err != nil {
			panic(fmt.Sprintf("got error while waiting for user to input the device code: %s", err))
		}
		fmt.Println("Access token is " + result.AccessToken)
		return
	}
	fmt.Println("Access token is " + authResult.AccessToken)
}

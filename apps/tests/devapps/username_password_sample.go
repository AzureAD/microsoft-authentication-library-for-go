// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

func acquireByUsernamePasswordPublic(ctx context.Context) {
	config := CreateConfig("config.json")
	app, err := public.New(config.ClientID, public.WithCache(cacheAccessor), public.WithAuthority(config.Authority))
	if err != nil {
		panic(err)
	}

	// look in the cache to see if the account to use has been cached
	var userAccount public.Account
	accounts, err := app.Accounts(ctx)
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
	result, err := app.AcquireTokenSilent(
		context.Background(),
		config.Scopes,
		public.WithSilentAccount(userAccount),
	)
	if err != nil {
		// either there's no applicable token in the cache or something failed
		log.Println(err)
		// either there was no cached account/token or the call to AcquireTokenSilent() failed
		// make a new request to AAD
		result, err = app.AcquireTokenByUsernamePassword(
			context.Background(),
			config.Scopes,
			config.Username,
			config.Password,
		)
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("Access token is " + result.AccessToken)
}

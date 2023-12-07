// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Keep the ConfidentialClient application object around, because it maintains a token cache
var _app *confidential.Client

func acquireTokenClientSecret() {
	config := CreateConfig("confidential_config.json")

	if _app == nil {
		cred, err := confidential.NewCredFromSecret(config.ClientSecret)
		if err != nil {
			log.Fatal(err)
		}
		app, err := confidential.New(config.Authority, config.ClientID, cred)
		if err != nil {
			log.Fatal(err)
		}
		_app = &app
	}

	result, err := _app.AcquireTokenByCredential(context.Background(), config.Scopes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("A Bearer token was acquired, it expires on: ", result.ExpiresOn)
}

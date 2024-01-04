// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

var _config1 *Config = CreateConfig("confidential_config.json")

// Keep the ConfidentialClient application object around, because it maintains a token cache
// For simplicity, the sample uses global variables.
// For user flows (web site, web api) or for large multi-tenant apps use a cache per user or per tenant
var _app1 *confidential.Client = createAppWithSecret()

func createAppWithSecret() *confidential.Client {

	cred, err := confidential.NewCredFromSecret(_config1.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}
	app, err := confidential.New(_config1.Authority, _config1.ClientID, cred)
	if err != nil {
		log.Fatal(err)
	}

	return &app
}

func acquireTokenClientSecret() {

	result, err := _app1.AcquireTokenByCredential(context.Background(), _config1.Scopes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("A Bearer token was acquired, it expires on: ", result.ExpiresOn)
}

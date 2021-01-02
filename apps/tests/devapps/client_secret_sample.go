// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"

	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func tryClientSecretFlow(app confidential.Client) {
	result, err := app.AcquireTokenByCredential(context.Background(), confidentialConfig.Scopes)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Println("Access token is: " + accessToken)
}

func acquireTokenClientSecret() {
	cred, err := confidential.NewCredFromSecret(confidentialConfig.ClientSecret)
	if err != nil {
		log.Fatal(err)
	}

	app, err := confidential.New("myUser", confidentialConfig.ClientID, cred, confidential.Accessor(cacheAccessor), confidential.Authority(confidentialConfig.Authority))
	if err != nil {
		log.Fatal(err)
	}

	result, err := app.AcquireTokenSilent(context.Background(), confidentialConfig.Scopes, nil)
	if err != nil {
		log.Println(err)
		tryClientSecretFlow(app)
	} else {
		accessToken := result.GetAccessToken()
		log.Println("Access token is: " + accessToken)
	}
}

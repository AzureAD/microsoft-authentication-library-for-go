// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
	log "github.com/sirupsen/logrus"
)

func tryClientCertificateFlow(confidentialClientApp *msal.ConfidentialClientApplication) {
	result, err := confidentialClientApp.AcquireTokenByClientCredential(context.Background(), confidentialConfig.Scopes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Access token is " + result.GetAccessToken())
}

func acquireTokenClientCertificate() {
	file, err := os.Open(confidentialConfig.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	key, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := msal.CreateClientCredentialFromCertificate(confidentialConfig.Thumbprint, key)
	if err != nil {
		log.Fatal(err)
	}
	options := msal.DefaultConfidentialClientApplicationOptions()
	options.Accessor = cacheAccessor
	confidentialClientApp, err := msal.NewConfidentialClientApplication(confidentialConfig.ClientID, confidentialConfig.Authority, certificate, &options)
	if err != nil {
		log.Fatal(err)
	}
	result, err := confidentialClientApp.AcquireTokenSilent(context.Background(), confidentialConfig.Scopes, nil)
	if err != nil {
		log.Info(err)
		tryClientCertificateFlow(confidentialClientApp)
	} else {
		fmt.Println("Access token is " + result.GetAccessToken())
	}
}

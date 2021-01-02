// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func tryClientCertificateFlow(app confidential.Client) {
	result, err := app.AcquireTokenByCredential(context.Background(), confidentialConfig.Scopes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Access token is " + result.GetAccessToken())
}

// This needs to be repaired.  We moved from "thumbprint" to requiring the x509 certificate and key
// as this is how you would do this in a Go world.
/*
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
	// confidential.NewCredFromCert()
	certificate, err := msal.CreateClientCredentialFromCertificate(confidentialConfig.Thumbprint, key)
	if err != nil {
		log.Fatal(err)
	}
	options := msal.DefaultConfidentialClientApplicationOptions()
	options.Accessor = cacheAccessor
	options.Authority = confidentialConfig.Authority
	confidentialClientApp, err := msal.NewConfidentialClientApplication(confidentialConfig.ClientID, certificate, &options)
	if err != nil {
		log.Fatal(err)
	}
	result, err := confidentialClientApp.AcquireTokenSilent(context.Background(), confidentialConfig.Scopes, nil)
	if err != nil {
		log.Println(err)
		tryClientCertificateFlow(confidentialClientApp)
	} else {
		fmt.Println("Access token is " + result.GetAccessToken())
	}
}
*/

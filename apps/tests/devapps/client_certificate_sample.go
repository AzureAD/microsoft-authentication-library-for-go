// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func acquireTokenClientCertificate() {
	config := CreateConfig("confidential_config.json")

	pemData, err := os.ReadFile(config.PemData)
	if err != nil {
		log.Fatal(err)
	}

	// This extracts our public certificates and private key from the PEM file. If it is
	// encrypted, the second argument must be password to decode.
	certs, privateKey, err := confidential.CertFromPEM(pemData, "")
	if err != nil {
		log.Fatal(err)
	}
	cred, err := confidential.NewCredFromCert(certs, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	app, err := confidential.New(config.Authority, config.ClientID, cred, confidential.WithCache(cacheAccessor))
	if err != nil {
		log.Fatal(err)
	}

	result, err := app.AcquireTokenByCredential(context.Background(), config.Scopes)

	fmt.Println("Got a token using the certificate. It expires on", result.ExpiresOn)
}

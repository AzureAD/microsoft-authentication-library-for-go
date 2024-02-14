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

var _config2 *Config = CreateConfig("confidential_config.json")

// Keep the ConfidentialClient application object around, because it maintains a token cache
// For simplicity, the sample uses global variables.
// For user flows (web site, web api) or for large multi-tenant apps use a cache per user or per tenant
var _app2 *confidential.Client = createAppWithCert()

func createAppWithCert() *confidential.Client {

	pemData, err := os.ReadFile(_config2.PemData)
	if err != nil {
		log.Fatal(err)
	}

	// This extracts our public certificates and private key from the PEM file. If it is
	// encrypted, the second argument must be password to decode.
	// IMPORTANT SECURITY NOTICE: never store passwords in code. The recommended pattern is to keep the certificate in a vault (e.g. Azure KeyVault)
	// and to download it when the application starts.
	certs, privateKey, err := confidential.CertFromPEM(pemData, "")
	if err != nil {
		log.Fatal(err)
	}
	cred, err := confidential.NewCredFromCert(certs, privateKey)
	if err != nil {
		log.Fatal(err)
	}
	app, err := confidential.New(_config2.Authority, _config2.ClientID, cred, confidential.WithCache(cacheAccessor))
	if err != nil {
		log.Fatal(err)
	}
	return &app
}

func acquireTokenClientCertificate() {

	result, err := _app2.AcquireTokenByCredential(context.Background(), _config1.Scopes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("A Bearer token was acquired, it expires on: ", result.ExpiresOn)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
	log "github.com/sirupsen/logrus"
)

func tryClientCertificateFlow(confidentialClientApp *msal.ConfidentialClientApplication) {
	certificateParams := msal.CreateAcquireTokenClientCredentialParameters(
		confidentialConfig.Scopes)
	result, err := confidentialClientApp.AcquireTokenByClientCredential(certificateParams)
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
	confidentialClientApp, err := msal.CreateConfidentialClientApplication(
		confidentialConfig.ClientID, confidentialConfig.Authority, certificate)
	if err != nil {
		log.Fatal(err)
	}
	confidentialClientApp.SetCacheAccessor(cacheAccessor)
	silentParams := msal.CreateAcquireTokenSilentParameters(confidentialConfig.Scopes)
	result, err := confidentialClientApp.AcquireTokenSilent(silentParams)
	if err != nil {
		log.Info(err)
		tryClientCertificateFlow(confidentialClientApp)
	} else {
		fmt.Println("Access token is " + result.GetAccessToken())
	}
}

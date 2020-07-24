// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

func tryClientCertificateFlow(confidentialClientApp *msalgo.ConfidentialClientApplication) {
	certificateParams := msalgo.CreateAcquireTokenClientAssertionParameters(
		confidentialConfig.Scopes)
	result, err := confidentialClientApp.AcquireTokenByClientAssertion(certificateParams)
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
	confidentialClientApp := msalgo.CreateConfidentialClientApplicationFromCertificate(
		confidentialConfig.ClientID, confidentialConfig.Authority, confidentialConfig.Thumbprint, key)
	confidentialClientApp.SetCacheAccessor(cacheAccessor)
	silentParams := msalgo.CreateAcquireTokenSilentParameters(confidentialConfig.Scopes)
	result, err := confidentialClientApp.AcquireTokenSilent(silentParams)
	if err != nil {
		log.Info(err)
		tryClientCertificateFlow(confidentialClientApp)
	} else {
		fmt.Println("Access token is " + result.GetAccessToken())
	}
}

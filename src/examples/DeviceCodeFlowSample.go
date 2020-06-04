// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"fmt"
	"time"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	log "github.com/sirupsen/logrus"
)

func setCancelTimeout(seconds int, cancelChannel chan bool) {
	time.Sleep(time.Duration(seconds) * time.Second)
	cancelChannel <- true
}

func acquireTokenDeviceCode() {
	cancelTimeout := 100
	config := CreateConfig("config.json")
	pcaParams := createPCAParams(config.GetClientID(), config.GetAuthority())
	publicClientApp, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(config.GetScopes())
	cancelChannel := make(chan bool)
	resultChannel := make(chan msalgo.IAuthenticationResult)
	errChannel := make(chan error)
	go func() {
		result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams, cancelChannel)
		errChannel <- err
		resultChannel <- result
	}()
	var deviceCodeResult msalgo.IDeviceCodeResult
	deviceCodeResult = deviceCodeParams.GetDeviceCodeResult()
	for deviceCodeResult.GetMessage() == "" {
		continue
	}
	fmt.Println("Message is: " + deviceCodeResult.GetMessage())
	go setCancelTimeout(cancelTimeout, cancelChannel)
	err = <-errChannel
	if err != nil {
		log.Fatal(err)
	}
	result := <-resultChannel
	fmt.Println("Access token is " + result.GetAccessToken())
}

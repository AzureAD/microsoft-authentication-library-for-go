// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"time"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

func deviceCodeCallback(deviceCodeResult msalgo.IDeviceCodeResult) {
	log.Infof(deviceCodeResult.GetMessage())
}

func setCancelTimeout(seconds int, cancelChannel chan bool) {
	time.Sleep(time.Duration(seconds) * time.Second)
	cancelChannel <- true
}

func acquireTokenDeviceCode() {
	cancelTimeout := 100 //Change this for cancel timeout
	config := CreateConfig("config.json")
	pcaParams := createPCAParams(config.GetClientID(), config.GetAuthority())
	publicClientApp, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	cancelCtx, cancelFunc := context.WithTimeout(context.Background(), time.Duration(cancelTimeout)*time.Second)
	defer cancelFunc()
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(cancelCtx, config.GetScopes(), deviceCodeCallback)
	resultChannel := make(chan msalgo.IAuthenticationResult)
	errChannel := make(chan error)
	go func() {
		result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams)
		errChannel <- err
		resultChannel <- result
	}()
	err = <-errChannel
	if err != nil {
		log.Fatal(err)
	}
	result := <-resultChannel
	fmt.Println("Access token is " + result.GetAccessToken())
}

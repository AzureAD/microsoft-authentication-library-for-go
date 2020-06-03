// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"time"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	log "github.com/sirupsen/logrus"
)

func acquireTokenDeviceCode() {
	config := CreateConfig("config.json")
	pcaParams := createPCAParams(config.GetClientID(), config.GetAuthority())
	publicClientApp, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(config.GetScopes())
	req, err := publicClientApp.AcquireDeviceCode(deviceCodeParams)
	//deviceCodeResult := req.GetDeviceCodeResult() // can use this line to get the deviceCodeResult
	if err != nil {
		log.Fatal(err)
	}
	result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams, req)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

func acquireTokenDeviceCodeWithCancel() {
	cancelTimeout := 10 //User can set this timeout to be what they want in seconds
	config := CreateConfig("config.json")
	pcaParams := createPCAParams(config.GetClientID(), config.GetAuthority())
	publicClientApp, err := msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters(config.GetScopes())
	req, err := publicClientApp.AcquireDeviceCode(deviceCodeParams)
	//deviceCodeResult := req.GetDeviceCodeResult() // can use this line to get the deviceCodeResult
	if err != nil {
		log.Fatal(err)
	}
	resultChannel := make(chan msalgo.IAuthenticationResult)
	errChannel := make(chan error)
	go func() {
		result, err := publicClientApp.AcquireTokenByDeviceCode(deviceCodeParams, req)
		resultChannel <- result
		errChannel <- err
	}()
	time.Sleep(time.Duration(cancelTimeout) * time.Second)
	req.CancelRequest()
	result := <-resultChannel
	err = <-errChannel
	close(errChannel)
	close(resultChannel)
	if err != nil {
		log.Fatal(err)
	}
	accessToken := result.GetAccessToken()
	log.Info("Access token is: " + accessToken)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"errors"
	"fmt"
	"net/http"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	log "github.com/sirupsen/logrus"
)

const PORT = ":3000"

var config = CreateConfig("config.json")
var pcaParams = createPCAParams(config.GetClientID(), config.GetAuthority())
var publicClientApp *msalgo.PublicClientApplication
var err error
var authCodeParams *msalgo.AcquireTokenInteractiveParameters

func redirectToURL(w http.ResponseWriter, r *http.Request) {
	// Creating the Public Client Application

	authURL, err := publicClientApp.AcquireAuthCode(authCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func getToken(w http.ResponseWriter, r *http.Request) {
	codes, ok := r.URL.Query()["code"]
	if !ok || len(codes[0]) < 1 {
		log.Fatal(errors.New("Parameter code missing"))
	}
	code := codes[0]
	authCodeParams.SetCode(code)
	result, err := publicClientApp.AcquireTokenInteractive(authCodeParams, code)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Access token is " + result.GetAccessToken())
}

func acquireByAuthorizationCodePublic() {
	pcaParams := createPCAParams(config.GetClientID(), config.GetAuthority())
	publicClientApp, err = msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}
	authCodeParams = msalgo.CreateAcquireTokenInteractiveParameters(config.GetScopes(), config.GetRedirectURI())
	http.HandleFunc("/", redirectToURL)
	http.HandleFunc("/redirect", getToken)
	log.Fatal(http.ListenAndServe(PORT, nil))
}

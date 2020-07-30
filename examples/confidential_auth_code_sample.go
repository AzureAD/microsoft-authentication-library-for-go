// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

var (
	confidentialConfig         = createConfig("confidential_config.json")
	confidentialClientAuthCode *msalgo.ConfidentialClientApplication
)

func redirectToURLConfidential(w http.ResponseWriter, r *http.Request) {
	// Getting the URL to redirect to acquire the authorization code
	authCodeURLParams := msalgo.CreateAuthorizationCodeURLParameters(
		confidentialConfig.ClientID,
		confidentialConfig.RedirectURI,
		confidentialConfig.Scopes,
		confidentialConfig.CodeChallenge,
	)
	authCodeURLParams.State = confidentialConfig.State
	authURL, err := confidentialClientAuthCode.CreateAuthCodeURL(authCodeURLParams)
	if err != nil {
		log.Fatal(err)
	}
	// Redirecting to the URL we have received
	log.Info(authURL)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func getTokenConfidential(w http.ResponseWriter, r *http.Request) {
	// Getting the authorization code from the URL's query
	states, ok := r.URL.Query()["state"]
	if !ok || len(states[0]) < 1 {
		log.Fatal(errors.New("State parameter missing, can't verify authorization code"))
	}
	codes, ok := r.URL.Query()["code"]
	if !ok || len(codes[0]) < 1 {
		log.Fatal(errors.New("Authorization code missing"))
	}
	if states[0] != config.State {
		log.Fatal(errors.New("State parameter is incorrect"))
	}
	code := codes[0]
	// Getting the access token using the authorization code
	authCodeParams := msalgo.CreateAcquireTokenAuthCodeParameters(
		confidentialConfig.Scopes,
		confidentialConfig.RedirectURI,
		confidentialConfig.CodeChallenge,
	)
	authCodeParams.Code = code
	result, err := confidentialClientAuthCode.AcquireTokenByAuthCode(authCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	// Prints the access token on the webpage
	fmt.Fprintf(w, "Access token is "+result.GetAccessToken())
}

func acquireByAuthorizationCodeConfidential() {
	// Uncomment this to use client secret
	/*confidentialClientAuthCode = msalgo.CreateConfidentialClientApplicationFromSecret(
	confidentialConfig.ClientID, confidentialConfig.Authority, confidentialConfig.ClientSecret)*/
	file, err := os.Open(confidentialConfig.KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	key, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}
	confidentialClientAuthCode = msalgo.CreateConfidentialClientApplicationFromCertificate(
		confidentialConfig.ClientID, confidentialConfig.Authority, confidentialConfig.Thumbprint, key)
	http.HandleFunc("/", redirectToURLConfidential)
	// The redirect uri set in our app's registration is http://localhost:port/redirect
	http.HandleFunc("/redirect", getTokenConfidential)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

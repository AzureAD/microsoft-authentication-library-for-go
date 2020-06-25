// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"errors"
	"fmt"
	"net/http"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

const port = "3000"

var config = createConfig("config.json")
var pcaParams = createPCAParams(config.ClientID, config.Authority)
var publicClientApp *msalgo.PublicClientApplication
var err error

func redirectToURL(w http.ResponseWriter, r *http.Request) {
	// Getting the URL to redirect to acquire the authorization code
	authCodeURLParams := msalgo.CreateAuthorizationCodeURLParameters(config.ClientID, config.RedirectURI, config.Scopes, config.CodeChallenge)
	authCodeURLParams.SetState(config.State)
	authURL, err := publicClientApp.CreateAuthCodeURL(authCodeURLParams)
	if err != nil {
		log.Fatal(err)
	}
	// Redirecting to the URL we have received
	log.Info(authURL)
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func getToken(w http.ResponseWriter, r *http.Request) {
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
	authCodeParams := msalgo.CreateAcquireTokenAuthCodeParameters(config.Scopes, config.RedirectURI, config.CodeChallenge)
	authCodeParams.SetCode(code)
	result, err := publicClientApp.AcquireTokenByAuthCode(authCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	// Prints the access token on the webpage
	fmt.Fprintf(w, "Access token is "+result.GetAccessToken())
}

func acquireByAuthorizationCodePublic() {
	publicClientApp, err = msalgo.CreatePublicClientApplication(pcaParams)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", redirectToURL)
	// The redirect uri set in our app's registration is http://localhost:port/redirect
	http.HandleFunc("/redirect", getToken)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

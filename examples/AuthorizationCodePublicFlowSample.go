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

const port = ":3000"

var config = CreateConfig("config.json")
var pcaParams = createPCAParams(config.ClientID, config.Authority)
var publicClientApp *msalgo.PublicClientApplication
var err error
var authCodeParams *msalgo.AcquireTokenAuthCodeParameters

func redirectToURL(w http.ResponseWriter, r *http.Request) {
	// Getting the URL to redirect to acquire the authorization code
	authURL, err := publicClientApp.AcquireAuthCodeURL(authCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	// Redirecting to the URL we have received
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

func getToken(w http.ResponseWriter, r *http.Request) {
	// Getting the authorization code from the URL's query
	codes, ok := r.URL.Query()["code"]
	if !ok || len(codes[0]) < 1 {
		log.Fatal(errors.New("Parameter code missing"))
	}
	code := codes[0]
	// Getting the access token using the authorization code
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
	authCodeParams = msalgo.CreateAcquireTokenAuthCodeParameters(config.Scopes, config.RedirectURI, config.CodeChallenge, config.CodeChallengeMethod)
	http.HandleFunc("/", redirectToURL)
	// The redirect uri set in our app's registration is http://localhost:port/redirect
	http.HandleFunc("/redirect", getToken)
	log.Fatal(http.ListenAndServe(port, nil))
}

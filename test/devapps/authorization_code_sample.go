// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
	log "github.com/sirupsen/logrus"
)

func redirectToURL(w http.ResponseWriter, r *http.Request) {
	// Getting the URL to redirect to acquire the authorization code
	authCodeURLParams := msal.CreateAuthorizationCodeURLParameters(config.ClientID, config.RedirectURI, config.Scopes)
	authCodeURLParams.CodeChallenge = config.CodeChallenge
	authCodeURLParams.State = config.State
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
	result, err := publicClientApp.AcquireTokenByAuthCode(context.Background(), config.Scopes, &msal.AcquireTokenByAuthCodeOptions{
		Code:          code,
		CodeChallenge: config.CodeChallenge,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Prints the access token on the webpage
	fmt.Fprintf(w, "Access token is "+result.GetAccessToken())
}

func acquireByAuthorizationCodePublic() {
	options := msal.DefaultPublicClientApplicationOptions()
	options.Authority = config.Authority
	publicClientApp = msal.NewPublicClientApplication(config.ClientID, &options)
	http.HandleFunc("/", redirectToURL)
	// The redirect uri set in our app's registration is http://localhost:port/redirect
	http.HandleFunc("/redirect", getToken)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

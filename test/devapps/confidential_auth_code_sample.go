// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/msalbase"
)

var (
	accessToken                string
	confidentialConfig         = CreateConfig("confidential_config.json")
	confidentialClientAuthCode *msal.ConfidentialClientApplication
)

func redirectToURLConfidential(w http.ResponseWriter, r *http.Request) {
	// Getting the URL to redirect to acquire the authorization code
	authCodeURLParams := msal.CreateAuthorizationCodeURLParameters(
		confidentialConfig.ClientID,
		confidentialConfig.RedirectURI,
		confidentialConfig.Scopes,
	)
	authCodeURLParams.CodeChallenge = confidentialConfig.CodeChallenge
	authCodeURLParams.State = confidentialConfig.State
	authURL, err := confidentialClientAuthCode.CreateAuthCodeURL(context.Background(), authCodeURLParams)
	if err != nil {
		log.Fatal(err)
	}
	// Redirecting to the URL we have received
	log.Println(authURL)
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
	result, err := confidentialClientAuthCode.AcquireTokenByAuthCode(context.Background(), confidentialConfig.Scopes, &msal.AcquireTokenByAuthCodeOptions{
		Code:          code,
		CodeChallenge: confidentialConfig.CodeChallenge,
	})
	if err != nil {
		log.Fatal(err)
	}
	// Prints the access token on the webpage
	fmt.Fprintf(w, "Access token is "+result.GetAccessToken())
	accessToken = result.GetAccessToken()
}

func acquireByAuthorizationCodeConfidential() {
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

	options := msal.DefaultConfidentialClientApplicationOptions()
	options.Accessor = cacheAccessor
	options.Authority = confidentialConfig.Authority
	confidentialClientAuthCode, err := msal.NewConfidentialClientApplication(confidentialConfig.ClientID, certificate, &options)
	if err != nil {
		log.Fatal(err)
	}
	var userAccount msalbase.Account
	for _, account := range confidentialClientAuthCode.Accounts() {
		if account.GetUsername() == confidentialConfig.Username {
			userAccount = account
		}
	}
	result, err := confidentialClientAuthCode.AcquireTokenSilent(
		context.Background(),
		confidentialConfig.Scopes,
		&msal.AcquireTokenSilentOptions{
			Account: userAccount,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Access token is " + result.GetAccessToken())
	accessToken = result.GetAccessToken()

	http.HandleFunc("/", redirectToURLConfidential)
	// The redirect uri set in our app's registration is http://localhost:port/redirect
	http.HandleFunc("/redirect", getTokenConfidential)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

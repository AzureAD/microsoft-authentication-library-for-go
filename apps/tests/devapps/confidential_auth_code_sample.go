// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

/*
var (
	accessToken        string
	confidentialConfig = CreateConfig("confidential_config.json")
	app                confidential.Client
)

// TODO(msal): I'm not sure what to do here with the CodeChallenge and State. authCodeURLParams
// is no more.  CodeChallenge is only used now in a confidential.AcquireTokenByAuthCode(), which
// this is not using.  Maybe now this is a two step process????
func redirectToURLConfidential(w http.ResponseWriter, r *http.Request) {
	// Getting the URL to redirect to acquire the authorization code
	authCodeURLParams.CodeChallenge = confidentialConfig.CodeChallenge
	authCodeURLParams.State = confidentialConfig.State
	authURL, err := app.AuthCodeURL(context.Background(), confidentialConfig.ClientID, confidentialConfig.RedirectURI, confidentialConfig.Scopes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	// Redirecting to the URL we have received
	log.Println("redirecting to auth: ", authURL)
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
	result, err := app.AcquireTokenByAuthCode(
		context.Background(),
		confidentialConfig.Scopes,
		confidential.CodeChallenge(code, confidentialConfig.CodeChallenge),
	)
	if err != nil {
		log.Fatal(err)
	}
	// Prints the access token on the webpage
	fmt.Fprintf(w, "Access token is "+result.GetAccessToken())
	accessToken = result.GetAccessToken()
}

// TODO(msal): Needs to use an x509 certificate like the other now that we are not using a
// thumbprint directly.
/*
func acquireByAuthorizationCodeConfidential(ctx context.Context) {
	key, err := os.ReadFile(confidentialConfig.KeyFile)
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
	app, err := msal.NewConfidentialClientApplication(confidentialConfig.ClientID, certificate, &options)
	if err != nil {
		log.Fatal(err)
	}
	var userAccount shared.Account
	for _, account := range app.Accounts(ctx) {
		if account.PreferredUsername == confidentialConfig.Username {
			userAccount = account
		}
	}
	result, err := app.AcquireTokenSilent(
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
*/

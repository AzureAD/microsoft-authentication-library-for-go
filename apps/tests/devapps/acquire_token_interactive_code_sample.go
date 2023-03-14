// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

// To use browser login use "Mobile and desktop applications" in your App Registration's Authentication, see:
// https://stackoverflow.com/questions/61231144/getting-access-tokens-from-postman-tokens-issued-for-the-single-page-applicati

// Be aware of the callback restrictions for localhost callbacks, see:
// https://learn.microsoft.com/en-us/azure/active-directory/develop/reply-url#localhost-exceptions

/*
import (
	"context"
	"fmt"
	msal "github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	clientId    = "<client id>"
	authority   = "https://login.microsoftonline.com/<token id>/oauth2/v2.0/authorize"
	redirectUri = "<callback>"
)

func main() {
	publicClientApp, err := msal.New(clientId, msal.WithAuthority(authority))
	if err != nil {
		panic(err)
	}
	ar, err := publicClientApp.AcquireTokenInteractive(context.Background(), []string{"openid"}, msal.WithRedirectURI(redirectUri))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Username: %s; accesstoken: %v\n", ar.IDToken.Name, ar.AccessToken)
}
*/

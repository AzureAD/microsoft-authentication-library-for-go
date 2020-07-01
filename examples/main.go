package main

import (
	"os"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
)

var config = createConfig("config.json")
var pcaParams = createPCAParams(config.ClientID, config.Authority)
var publicClientApp *msalgo.PublicClientApplication
var err error
var authCodeParams *msalgo.AcquireTokenAuthCodeParameters

func main() {
	exampleType := os.Args[1]
	if exampleType == "1" {
		acquireTokenDeviceCode()
	} else if exampleType == "2" {
		acquireByAuthorizationCodePublic()
	} else if exampleType == "3" {
		acquireByUsernamePasswordPublic()
	}
}

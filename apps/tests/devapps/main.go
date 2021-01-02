package main

import (
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

const port = "3000"

var (
	config          = CreateConfig("config.json")
	publicClientApp *msal.PublicClientApplication
	cacheAccessor   = &TokenCache{"serialized_cache.json"}
)

func main() {
	// TODO(jdoak): This is pretty yikes. At least we should use the flag package.
	exampleType := os.Args[1]
	if exampleType == "1" {
		acquireTokenDeviceCode()
		/*} else if exampleType == "2" {
		acquireByAuthorizationCodePublic()
		*/
	} else if exampleType == "3" {
		acquireByUsernamePasswordPublic()
	} else if exampleType == "4" {
		acquireByAuthorizationCodeConfidential()
	} else if exampleType == "5" {
		acquireTokenClientSecret()
	} else if exampleType == "6" {
		acquireTokenClientCertificate()
	}
}

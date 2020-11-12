package main

import (
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

const port = "3000"

var config = createConfig("config.json")
var publicClientApp *msal.PublicClientApplication
var err error
var cacheAccessor = &SampleCacheAccessor{"serialized_cache.json"}

func main() {
	exampleType := os.Args[1]
	if exampleType == "1" {
		acquireTokenDeviceCode()
	} else if exampleType == "2" {
		acquireByAuthorizationCodePublic()
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

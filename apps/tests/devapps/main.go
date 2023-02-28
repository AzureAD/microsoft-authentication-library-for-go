package main

import (
	"context"
	"os"
)

var (
	//config        = CreateConfig("config.json")
	cacheAccessor = &TokenCache{file: "serialized_cache.json"}
)

func main() {
	ctx := context.Background()

	// TODO(msal): This is pretty yikes. At least we should use the flag package.
	exampleType := os.Args[1]
	if exampleType == "1" {
		acquireTokenDeviceCode()
		/*} else if exampleType == "2" {
		acquireByAuthorizationCodePublic()
		*/
	} else if exampleType == "3" {
		acquireByUsernamePasswordPublic(ctx)
	} else if exampleType == "4" {
		panic("currently not implemented")
		//acquireByAuthorizationCodeConfidential()
	} else if exampleType == "5" {
		acquireTokenClientSecret()
	} else if exampleType == "6" {
		acquireTokenClientCertificate()
	}
}

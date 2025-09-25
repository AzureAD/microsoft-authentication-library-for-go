package main

import (
	"context"
)

var (
	//config        = CreateConfig("config.json") reenable when config is implemented
	cacheAccessor = &TokenCache{file: "serialized_cache.json"}
)

func main() {
	ctx := context.Background()

	// Choose a sammple to run.
	exampleType := "5"

	if exampleType == "1" {
		acquireTokenDeviceCode()
		/*} else if exampleType == "2" {
		acquireByAuthorizationCodePublic()
		*/
	} else if exampleType == "3" {
		// This sample has been removed due to deprecated AcquireTokenByUsernamePassword API usage
		panic("username/password sample has been removed - use a more secure authentication flow")
	} else if exampleType == "4" {
		panic("currently not implemented")
		//acquireByAuthorizationCodeConfidential()
	} else if exampleType == "5" {
		// This sample does not use a serialized cache - it relies on in-memory cache by reusing the app object
		// This works well for app tokens, because there is only 1 token per resource, per tenant.
		acquireTokenClientSecret()

		// this time the token comes from the cache!
		acquireTokenClientSecret()
	} else if exampleType == "6" {
		// This sample does not use a serialized cache - it relies on in-memory cache by reusing the app object
		// This works well for app tokens, because there is only 1 token per resource, per tenant.
		acquireTokenClientCertificate()

		// this time the token comes from the cache!
		acquireTokenClientCertificate()
	}
}

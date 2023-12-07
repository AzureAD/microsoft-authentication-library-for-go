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
		// This sample does not use a serialized cache - it relies on in-memory cache by reusing the app object
		// This works great for app tokens, because there is only 1 token per resource, per tenant and most
		// developers only require 1-2 tokens.
		acquireTokenClientSecret()

		// this time the token comes from the cache!
		acquireTokenClientSecret()
	} else if exampleType == "6" {
		// This samples	uses a serialized cache in a file. This is for demonstration purposes only of the caching interface.
		// Production confidential client apps use in-memory cache (see above sample) if they target a small number of tenants.
		// Multi-tenant apps needing tokens for million of tokens should use a distributed cache like Redis.
		acquireTokenClientCertificate()

		// this time the token comes from the cache!
		acquireTokenClientCertificate()
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// This example demonstrates the general pattern for authenticating with MSAL Go:
//   - create a client (only necessary at application start--it's best to reuse client instances)
//   - call AcquireTokenSilent() to search for a cached access token
//   - if the cache misses, acquire a new token
func Example() {
	cred, err := confidential.NewCredFromSecret("client_secret")
	if err != nil {
		// TODO: handle error
	}
	client, err := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred)
	if err != nil {
		// TODO: handle error
	}

	scopes := []string{"scope"}
	result, err := client.AcquireTokenSilent(context.TODO(), scopes)
	if err != nil {
		// cache miss, authenticate with another AcquireToken* method
		result, err = client.AcquireTokenByCredential(context.TODO(), scopes)
		if err != nil {
			// TODO: handle error
		}
	}

	// TODO: use access token
	_ = result.AccessToken
}

func ExampleNewCredFromCert_pem() {
	b, err := os.ReadFile("key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// This extracts our public certificates and private key from the PEM file. If it is
	// encrypted, the second argument must be password to decode.
	certs, priv, err := confidential.CertFromPEM(b, "")
	if err != nil {
		log.Fatal(err)
	}

	cred, err := confidential.NewCredFromCert(certs, priv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cred) // Simply here so cred is used, otherwise won't compile.
}

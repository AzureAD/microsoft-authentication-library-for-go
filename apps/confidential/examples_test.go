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

// This example demonstrates the general pattern for authenticating FMI-based confidential clients.
// It shows how to create a confidential client and acquire a token using an FMI path.
// This uses a RMA token as assertion for fetching the token
func ExampleClient_AcquireTokenByCredential_withFMIPath() {
	cred := confidential.NewCredFromAssertionCallback(
		func(ctx context.Context, aro confidential.AssertionRequestOptions) (string, error) {
			//TODO: implement logic to acquire RMA token
			return "fakeToken", nil
		})

	client, err := confidential.New("https://login.microsoftonline.com/your_tenant", "urn:microsoft:identity:fmi", cred)
	if err != nil {
		// TODO: handle error
	}

	scopes := []string{"scope"}
	result, err := client.AcquireTokenByCredential(context.TODO(), scopes, confidential.WithFMIPath("some/path"))
	if err != nil {
		// TODO: handle error
	}

	// TODO: use access token
	_ = result.AccessToken
}

// This example demonstrates requesting an mTLS-bound proof-of-possession token (token_type=mtls_pop)
// using a Subject Name + Issuer (SN/I) certificate as the client TLS certificate. The same
// certificate loaded for the credential is presented on the mutual-TLS handshake to the token
// endpoint, and the returned token is bound to it. The authority must be tenanted.
func ExampleClient_AcquireTokenByCredential_withMtlsProofOfPossession() {
	b, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	certs, priv, err := confidential.CertFromPEM(b, "")
	if err != nil {
		log.Fatal(err)
	}
	cred, err := confidential.NewCredFromCert(certs, priv)
	if err != nil {
		log.Fatal(err)
	}

	client, err := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred)
	if err != nil {
		// TODO: handle error
	}

	// The binding certificate is inferred from the credential created by NewCredFromCert.
	result, err := client.AcquireTokenByCredential(context.TODO(), []string{"https://vault.azure.net/.default"},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		// TODO: handle error
	}

	// result.Metadata.TokenType == "mtls_pop"; the public binding certificate and its thumbprint are
	// available for the caller to present to the resource.
	_ = result.AccessToken
	_ = result.BindingCertificate
	fmt.Println(result.BindingCertificateThumbprint())
}

// This example demonstrates the developer-orchestrated two-leg federated identity credential (FIC)
// flow where both legs are mTLS proof-of-possession. Leg 1 uses the SN/I certificate as the TLS
// client certificate to obtain a certificate-bound federated assertion; leg 2 presents that
// assertion together with the same binding certificate to obtain the final mtls_pop token.
func ExampleClient_AcquireTokenByCredential_ficMtlsProofOfPossession() {
	b, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	certs, priv, err := confidential.CertFromPEM(b, "")
	if err != nil {
		log.Fatal(err)
	}
	sni, err := confidential.NewCredFromCert(certs, priv)
	if err != nil {
		log.Fatal(err)
	}

	// Leg 1: SN/I cert -> cert-bound federated assertion, itself an mTLS PoP request.
	// The exchange audience is caller-supplied (generic S2S FIC uses api://AzureADTokenExchange).
	leg1App, err := confidential.New("https://login.microsoftonline.com/your_tenant", "leg1_client_id", sni)
	if err != nil {
		// TODO: handle error
	}
	leg1, err := leg1App.AcquireTokenByCredential(context.TODO(),
		[]string{"api://AzureADTokenExchange/.default"},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		// TODO: handle error
	}

	// Leg 2: federated assertion (jwt-pop) + binding cert -> final mtls_pop token.
	assertionCred := confidential.NewCredFromAssertionCallback(
		func(context.Context, confidential.AssertionRequestOptions) (string, error) {
			return leg1.AccessToken, nil
		})
	leg2App, err := confidential.New("https://login.microsoftonline.com/your_tenant", "final_client_id", assertionCred)
	if err != nil {
		// TODO: handle error
	}
	final, err := leg2App.AcquireTokenByCredential(context.TODO(), []string{"https://vault.azure.net/.default"},
		confidential.WithMtlsProofOfPossession(confidential.WithMtlsBindingCertificate(certs, priv)))
	if err != nil {
		// TODO: handle error
	}

	_ = final.AccessToken
}

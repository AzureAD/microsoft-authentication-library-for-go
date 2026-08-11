// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential_test

import (
	"context"
	"crypto"
	"crypto/tls"
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

	// result.Metadata.TokenType == "mtls_pop"; result.BindingCertificate is the *tls.Certificate the
	// token is bound to (leaf plus private key), ready to present to the resource on the TLS handshake.
	_ = result.AccessToken
	_ = result.BindingCertificate
	fmt.Println(result.BindingCertificateThumbprint())
}

// This example demonstrates using a non-exportable key -- such as a Windows KeyGuard (VBS-isolated)
// key, a CNG key handle, or an HSM-backed key -- to authenticate a confidential client. Such a key
// can never be retrieved as an *rsa.PrivateKey; it can only be surfaced as a crypto.Signer, which the
// caller implements over its key provider (MSAL adds no platform-specific dependencies).
//
// The credential works in every flow: MSAL signs the client assertion through the signer. This
// example additionally requests an mTLS-bound proof-of-possession token, the one flow that sends no
// client assertion at all because the certificate presented on the mutual-TLS handshake both
// authenticates the client and binds the token.
func ExampleNewCredFromTLSCertificate() {
	// signer is the application's crypto.Signer over the non-exportable key, and chain holds the
	// DER-encoded certificate chain, leaf first.
	var signer crypto.Signer
	var chain [][]byte

	cred, err := confidential.NewCredFromTLSCertificate(tls.Certificate{
		Certificate: chain,
		PrivateKey:  signer,
	})
	if err != nil {
		log.Fatal(err)
	}

	client, err := confidential.New("https://login.microsoftonline.com/your_tenant", "client_id", cred)
	if err != nil {
		// TODO: handle error
	}

	// MSAL passes the signer to the mTLS transport, which signs the TLS handshake with it. Without
	// WithMtlsProofOfPossession the same signer signs the private_key_jwt client assertion instead.
	result, err := client.AcquireTokenByCredential(context.TODO(), []string{"https://vault.azure.net/.default"},
		confidential.WithMtlsProofOfPossession())
	if err != nil {
		// TODO: handle error
	}

	_ = result.AccessToken
	fmt.Println(result.BindingCertificateThumbprint())
}

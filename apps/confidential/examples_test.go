// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
)

func ExampleNewCredFromCert_pem() {
	b, err := ioutil.ReadFile("key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// This extracts our public certificates and private key from the PEM file.
	// The private key must be in PKCS8 format. If it is encrypted, the second argument
	// must be password to decode.
	certs, priv, err := CertFromPEM(b, "")
	if err != nil {
		log.Fatal(err)
	}

	// PEM files can have multiple certs. This is usually for certificate chaining where roots
	// sign to leafs. Useful for TLS, not for this use case.
	if len(certs) > 1 {
		log.Fatal("too many certificates in PEM file")
	}

	cred := NewCredFromCert(certs[0], priv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cred) // Simply here so cred is used, otherwise won't compile.
}

// ExampleAcquireTokenByCredential gives an example of acquiring token by credential.
func ExampleAcquireTokenByCredential() {
	var tokenScope = []string{"the_scope"}
	var secret = "the_secret"

	//In this case, we are getting a credential using a secret.
	// We could also use an assertion (NewCredFromAssertion) or a certificate (NewCredFromCert) to obtain a credential.
	cred, err := NewCredFromSecret(secret)
	if err != nil {
		log.Fatalf("ExampleAcquireTokenByCredential: acquring token by credential %v", err)
	}
	client, err := New("fake_client_id", cred)
	if err != nil {
		log.Fatalf("ExampleAcquireTokenByCredential: acquring token by credential %v", err)
	}

	ctx := context.Background()
	token, err := client.AcquireTokenByCredential(ctx, tokenScope)
	if err != nil {
		log.Fatalf("ExampleAcquireTokenByCredential: acquring token by credential %v", err)
	}
	fmt.Println(token)

}

// ExampleAcquireTokenByAuthCode gives an example of acquiring token by auth code.
func ExampleAcquireTokenByAuthCode() {
	var tokenScope = []string{"the_scope"}
	var secret = "the_secret"

	//In this case, we are getting a credential using a secret.
	// We could also use an assertion (NewCredFromAssertion) or a certificate (NewCredFromCert) to obtain a credential.
	cred, err := NewCredFromSecret(secret)
	if err != nil {
		log.Fatalf("ExampleAcquireTokenByAuthCode: acquring token by auth code %v", err)
	}
	client, err := New("fake_client_id", cred)
	if err != nil {
		log.Fatalf("ExampleAcquireTokenByAuthCode: acquring token by auth code %v", err)
	}

	ctx := context.Background()
	token, err := client.AcquireTokenByAuthCode(ctx, "fake_auth_code", "fake_redirect_uri", tokenScope)
	if err != nil {
		log.Fatalf("ExampleAcquireTokenByAuthCode: acquring token by auth code %v", err)
	}
	fmt.Println(token)

}

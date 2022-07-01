// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential_test

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

func ExampleNewCredFromCert_pem() {
	b, err := ioutil.ReadFile("key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// This extracts our public certificates and private key from the PEM file. If it is
	// encrypted, the second argument must be password to decode.
	certs, priv, err := confidential.CertFromPEM(b, "")
	if err != nil {
		log.Fatal(err)
	}

	// PEM files can have multiple certs. This is usually for certificate chaining where roots
	// sign to leafs. Useful for TLS, not for this use case.
	if len(certs) > 1 {
		log.Fatal("too many certificates in PEM file")
	}

	cred := confidential.NewCredFromCert(certs[0], priv)
	fmt.Println(cred) // Simply here so cred is used, otherwise won't compile.
}

func ExampleNewCredFromCertChain() {
	b, err := ioutil.ReadFile("key.pem")
	if err != nil {
		// TODO: handle error
	}

	// CertFromPEM loads certificates and a private key from the PEM content. If
	// the content is encrypted, the second argument must be the password.
	certs, priv, err := confidential.CertFromPEM(b, "")
	if err != nil {
		// TODO: handle error
	}

	cred, err := confidential.NewCredFromCertChain(certs, priv)
	if err != nil {
		// TODO: handle error
	}
	_ = cred
}

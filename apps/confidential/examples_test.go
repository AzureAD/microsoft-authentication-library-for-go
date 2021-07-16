// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
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
	fmt.Println(cred) // Simply here so cred is used, otherwise won't compile.
}

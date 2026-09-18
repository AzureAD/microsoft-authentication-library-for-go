// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package attestation_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/attestation"
)

// Attestation is an optional import. The module embeds and securely
// materializes AttestationClientLib.dll, so the application does not deploy the
// native library separately.
func ExampleWithSupport() {
	client, err := managedidentity.New(managedidentity.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(
		context.TODO(),
		"https://vault.azure.net",
		managedidentity.WithMtlsProofOfPossession(),
		attestation.WithSupport(),
	)
	switch {
	case errors.Is(err, managedidentity.ErrAttestationUnavailable):
		fmt.Println("KeyGuard attestation is unavailable on this host")
		return
	case err != nil:
		log.Fatal(err)
	}

	fmt.Println(result.Metadata.TokenType) // "mtls_pop"
}

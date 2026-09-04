// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package managedidentity_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

// Acquire a certificate-bound (mtls_pop) token for a managed identity. The binding key is minted
// inside Virtualization-Based Security, so its private material never enters this process.
func ExampleWithMtlsProofOfPossession() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.Metadata.TokenType) // "mtls_pop"
	_ = result.BindingCertificate          // the certificate the token is bound to
}

// A bound token is only accepted when the same certificate is presented on the TLS handshake, so the
// binding certificate has to go into the transport used to call the resource.
func ExampleWithMtlsProofOfPossession_callingTheResource() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession())
	if err != nil {
		log.Fatal(err)
	}

	cert := *result.BindingCertificate
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// GetClientCertificate rather than Certificates: the certificate has to
				// be offered again on the renegotiated handshake, not just the first one.
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
				MinVersion: tls.VersionTLS12,
				// Azure resources that enforce token binding ask for the client
				// certificate by TLS renegotiation, after reading the request. Go
				// refuses renegotiation by default, and TLS 1.3 has no post-handshake
				// client auth in crypto/tls, so without these two settings the
				// connection is reset instead of authenticated.
				MaxVersion:    tls.VersionTLS12,
				Renegotiation: tls.RenegotiateOnceAsClient,
			},
		},
	}

	req, err := http.NewRequest(http.MethodGet,
		"https://myvault.vault.azure.net/secrets/mysecret?api-version=7.4", nil)
	if err != nil {
		log.Fatal(err)
	}
	// The scheme is mtls_pop, not Bearer. A resource that enforces binding rejects the token if it
	// arrives as Bearer or over a connection that did not present the certificate.
	req.Header.Set("Authorization", "mtls_pop "+result.AccessToken)
	req.Header.Set("x-ms-tokenboundauth", "true")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
}

// WithRequestOverMtls authenticates the transport with the same certificate but asks for an ordinary
// bearer token, for resources that do not understand mtls_pop.
func ExampleWithRequestOverMtls() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithRequestOverMtls())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.Metadata.TokenType) // "Bearer" — not bound to the certificate
}

// Binding failures are typed, so a caller can tell "this host cannot do it" from "this call was
// wrong". There is deliberately no silent downgrade to an unbound token.
func Example_handlingUnsupportedHosts() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	_, err = client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession())
	switch {
	case errors.Is(err, mi.ErrMtlsNotSupportedForPlatform):
		fmt.Println("not Windows: no KeyGuard available")
	case errors.Is(err, mi.ErrCredentialGuardNotAvailable):
		fmt.Println("Credential Guard/VBS is not enabled on this host")
	case errors.Is(err, mi.ErrMtlsPoPNotSupportedInIMDSv1):
		fmt.Println("this host serves IMDSv1 only")
	case errors.Is(err, mi.ErrMtlsPoPNotSupportedForSource):
		fmt.Println("this identity source has no v2 credential endpoint")
	case err != nil:
		log.Fatal(err)
	}
}

// Attestation is opt-in. Asking for it has IMDS bind the certificate to a Microsoft Azure
// Attestation statement proving the private key lives in Virtualization-based Security, which a
// resource can require.
//
// It needs AttestationClientLib.dll on the host. That library is native, is owned by the Azure
// attestation team, and ships in the Microsoft.Azure.Security.KeyGuardAttestation package rather
// than in this module, so deploying it alongside the binary is a step the application owns. MSAL
// .NET gets it from the same package; NuGet copies it next to the executable, which Go has no
// equivalent of.
//
// Having asked, a caller is never quietly handed a certificate without one: a host that cannot
// attest returns ErrAttestationUnavailable instead of a weaker credential.
func Example_attestedBinding() {
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		log.Fatal(err)
	}

	result, err := client.AcquireToken(context.TODO(), "https://vault.azure.net",
		mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
	switch {
	case errors.Is(err, mi.ErrAttestationUnavailable):
		fmt.Println("AttestationClientLib.dll is not deployed on this host")
		return
	case err != nil:
		log.Fatal(err)
	}

	fmt.Println(result.Metadata.TokenType) // "mtls_pop"
}

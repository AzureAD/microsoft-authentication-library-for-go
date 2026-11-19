//go:build e2e && windows && imdsv2soak
// +build e2e,windows,imdsv2soak

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func TestIMDSv2RenewalPreflight(t *testing.T) {
	testIMDSv2NaturalCertificateRenewal(t, true)
}

func TestSoakIMDSv2NaturalCertificateRenewal(t *testing.T) {
	testIMDSv2NaturalCertificateRenewal(t, false)
}

func testIMDSv2NaturalCertificateRenewal(t *testing.T, preflightOnly bool) {
	t.Helper()
	const (
		refreshWindow = 24 * time.Hour
		pollInterval  = 5 * time.Minute
		probeTimeout  = 90 * time.Second
	)
	vault, secret := os.Getenv("IMDSV2_E2E_VAULT"), os.Getenv("IMDSV2_E2E_SECRET")
	if vault == "" || secret == "" {
		t.Fatal("IMDSV2_E2E_VAULT and IMDSV2_E2E_SECRET are required")
	}
	target := url.URL{Scheme: "https", Host: vault, Path: "/secrets/" + secret, RawQuery: "api-version=7.4"}
	client, err := mi.New(mi.SystemAssigned())
	if err != nil {
		t.Fatal(err)
	}

	type binding struct {
		thumbprint string
		expires    time.Time
	}
	probe := func() binding {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		defer cancel()
		result, err := client.AcquireToken(ctx, imdsV2VaultResource, mi.WithMtlsProofOfPossession(), mi.WithAttestationSupport())
		if err != nil {
			t.Fatalf("acquiring an attested PoP token: %v", err)
		}
		cert := result.BindingCertificate
		if result.Metadata.TokenType != "mtls_pop" || cert == nil || cert.Leaf == nil {
			t.Fatal("acquisition did not return a PoP token with a parsed binding certificate")
		}
		thumbprint := result.BindingCertificateThumbprint()
		cnf, err := cnfThumbprint(result.AccessToken)
		if err != nil || thumbprint == "" || cnf != thumbprint {
			t.Fatal("the token's confirmation claim does not identify the returned certificate")
		}
		body, status, err := getBoundSecret(ctx, target.String(), result.AccessToken, *cert)
		if err != nil {
			t.Fatalf("calling the vault: %v", err)
		}
		if status != http.StatusOK {
			t.Fatalf("vault returned HTTP %d, want 200", status)
		}
		var response struct {
			Value string `json:"value"`
		}
		if err := json.Unmarshal([]byte(body), &response); err != nil || strings.TrimSpace(response.Value) == "" {
			t.Fatal("vault returned HTTP 200 without a non-empty secret value")
		}
		t.Logf("%s: vault read passed; cert=%s expires=%s public-key-sha256=%x",
			time.Now().UTC().Format(time.RFC3339), thumbprint, cert.Leaf.NotAfter.UTC().Format(time.RFC3339),
			sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo))
		return binding{thumbprint: thumbprint, expires: cert.Leaf.NotAfter}
	}

	baseline := probe()
	refreshAt := baseline.expires.Add(-refreshWindow)
	if !time.Now().Before(refreshAt) {
		t.Fatal("the baseline certificate is already in its refresh window; the test needs a pre-renewal baseline")
	}
	t.Logf("expecting natural renewal from %s", refreshAt.UTC().Format(time.RFC3339))
	if preflightOnly {
		t.Log("baseline verified; this preflight did not wait for renewal")
		return
	}
	if deadline, ok := t.Deadline(); ok && deadline.Before(refreshAt.Add(pollInterval+probeTimeout)) {
		t.Fatalf("increase -timeout to allow at least %s for the renewal probe", time.Until(refreshAt.Add(pollInterval+probeTimeout)).Round(time.Second))
	}

	for {
		time.Sleep(pollInterval)
		started := time.Now()
		current := probe()
		if current.thumbprint != baseline.thumbprint {
			if time.Now().Before(refreshAt) {
				t.Fatal("the certificate changed before the refresh window; this is not evidence of expiry-driven renewal")
			}
			if !current.expires.After(baseline.expires) {
				t.Fatal("the replacement certificate did not extend validity")
			}
			return
		}
		if !started.Before(refreshAt) {
			t.Fatal("acquisition still returned the original certificate after it entered its refresh window")
		}
	}
}

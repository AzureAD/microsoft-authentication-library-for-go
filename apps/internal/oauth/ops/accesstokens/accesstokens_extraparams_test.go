// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// TestExtraBodyParametersCannotOverwriteReservedKeys covers the guard inside addExtraBodyParameters.
// The helper runs last in every request builder and uses url.Values.Set, which overwrites, so an
// extra body parameter under a key MSAL owns would silently change what is being requested or how
// the client is authenticated. Nothing in this module can populate these keys today - only
// WithFMIPath and WithAttribute write ExtraBodyParameters, and both hardcode their key - so this
// covers a future caller-supplied extra-parameters API rather than a reachable hole.
//
// The guard lives in the shared helper, not at one call site, and this exercises it through three
// different request builders so a move back to a single call site fails here.
func TestExtraBodyParametersCannotOverwriteReservedKeys(t *testing.T) {
	reserved := []string{
		"client_assertion",
		"client_assertion_type",
		"req_cnf",
		"grant_type",
		"client_id",
		"token_type",
	}

	// Each entry drives addExtraBodyParameters from a different request builder.
	callers := map[string]func(client Client, ap authority.AuthParams) error{
		"FromClientSecret": func(client Client, ap authority.AuthParams) error {
			_, err := client.FromClientSecret(context.Background(), ap, "secret")
			return err
		},
		"FromAssertion": func(client Client, ap authority.AuthParams) error {
			_, err := client.FromAssertion(context.Background(), ap, "assertion")
			return err
		},
		"FromClientCertificate": func(client Client, ap authority.AuthParams) error {
			_, err := client.FromClientCertificate(context.Background(), ap)
			return err
		},
	}

	cert := selfSignedTLSCert(t)
	for name, call := range callers {
		for _, key := range reserved {
			t.Run(name+"/"+key, func(t *testing.T) {
				authParams := mtlsAuthParams(cert)
				authParams.ExtraBodyParameters = map[string]string{key: "attacker-controlled"}

				fake := &fakeURLCaller{}
				client := Client{Comm: fake, testing: true}

				err := call(client, authParams)
				if err == nil {
					t.Fatalf("%s with extra body parameter %q = nil error, want it rejected", name, key)
				}
				if !strings.Contains(err.Error(), key) {
					t.Errorf("error = %q, want it to name the rejected key %q", err, key)
				}
				// The request must not be sent at all, otherwise the overwritten value would
				// already be on the wire.
				if fake.gotQV != nil {
					t.Errorf("%s sent a request carrying %v despite the reserved key", name, fake.gotQV)
				}
			})
		}
	}
}

// TestExtraBodyParametersStillApplied is the control: keys MSAL does not own are still added, and an
// empty value is still skipped rather than rejected.
func TestExtraBodyParametersStillApplied(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)
	authParams.ExtraBodyParameters = map[string]string{
		"fmi_path":   "some/path",
		"attributes": "attr",
		"empty":      "",
	}

	fake := &fakeURLCaller{}
	client := Client{Comm: fake, testing: true}

	if _, err := client.FromClientCertificate(context.Background(), authParams); err != nil {
		t.Fatalf("FromClientCertificate() error: %v", err)
	}
	if got := fake.gotQV.Get("fmi_path"); got != "some/path" {
		t.Errorf("fmi_path = %q, want some/path", got)
	}
	if got := fake.gotQV.Get("attributes"); got != "attr" {
		t.Errorf("attributes = %q, want attr", got)
	}
	if _, ok := fake.gotQV["empty"]; ok {
		t.Error("an empty extra body parameter must not be sent")
	}
	// The values MSAL owns are untouched.
	if got := fake.gotQV.Get("token_type"); got != authority.AccessTokenTypeMtlsPoP {
		t.Errorf("token_type = %q, want %q", got, authority.AccessTokenTypeMtlsPoP)
	}
}

//go:build windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"strings"
	"testing"
)

func TestRequireHTTPS(t *testing.T) {
	for _, test := range []struct {
		name string
		url  string
		// wantErrContains is empty when the URL must be accepted
		wantErrContains string
	}{
		{name: "https", url: "https://vault.azure.net/.default"},
		{name: "https with a port", url: "https://localhost:8443/api"},
		// url.Parse lower-cases the scheme, which is what lets requireHTTPS compare it exactly
		{name: "uppercase scheme", url: "HTTPS://vault.azure.net"},
		{name: "mixed-case scheme", url: "HttPs://vault.azure.net"},
		{name: "http", url: "http://vault.azure.net", wantErrContains: "cleartext"},
		{name: "uppercase http", url: "HTTP://vault.azure.net", wantErrContains: "cleartext"},
		{name: "no scheme", url: "vault.azure.net", wantErrContains: "no scheme"},
		{name: "scheme-relative", url: "//vault.azure.net", wantErrContains: "no scheme"},
		{name: "empty", url: "", wantErrContains: "no scheme"},
		{name: "unparseable", url: "https://exa mple.com/\x7f", wantErrContains: "isn't a valid URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := requireHTTPS(test.url)
			if test.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), test.wantErrContains) {
				t.Fatalf("error %q doesn't mention %q", err, test.wantErrContains)
			}
		})
	}
}

// TestCallResourceRejectsPlaintext pins where the guard sits. The binding certificate is nil, so the
// only way this can return an error rather than panic is if the scheme is rejected before anything
// builds a transport or dials.
func TestCallResourceRejectsPlaintext(t *testing.T) {
	err := callResource(context.Background(), "http://localhost:0/secret", "a-token", nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("error %q doesn't mention the cleartext hazard", err)
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestRequireHTTPS(t *testing.T) {
	for _, test := range []struct {
		url     string
		wantErr bool
	}{
		{url: "https://vault.azure.net/"},
		{url: "https://localhost:8443/path"},
		{url: "http://vault.azure.net/", wantErr: true},
		{url: "//vault.azure.net/", wantErr: true},
		{url: "vault.azure.net", wantErr: true},
		{url: "https://", wantErr: true},
	} {
		err := requireHTTPS(test.url)
		if (err != nil) != test.wantErr {
			t.Errorf("requireHTTPS(%q) error = %v, wantErr %t", test.url, err, test.wantErr)
		}
	}
}

func TestRefuseResourceRedirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://redirect.example/target", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = refuseResourceRedirect(req, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing resource redirect") {
		t.Fatalf("refuseResourceRedirect() error = %v", err)
	}
}

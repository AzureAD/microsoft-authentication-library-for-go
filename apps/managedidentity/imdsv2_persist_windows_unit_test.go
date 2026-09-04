// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

// The client ID read back out of a restored certificate reaches a token-cache
// partition key. A certificate whose common name came back upper-cased would
// otherwise land in a different partition than the same identity acquired
// without the persisted certificate, so the process would hold two copies of
// the same token and refresh each of them separately.
func TestClientIDFromSubjectIsLowercased(t *testing.T) {
	for name, tc := range map[string]struct {
		cn   string
		want string
		ok   bool
	}{
		"upper-cased guid": {
			cn:   "9E9A2F51-4C1D-4B0E-9E88-2C6C3D3A1B2C",
			want: "9e9a2f51-4c1d-4b0e-9e88-2c6c3d3a1b2c",
			ok:   true,
		},
		"already lowercase": {
			cn:   "9e9a2f51-4c1d-4b0e-9e88-2c6c3d3a1b2c",
			want: "9e9a2f51-4c1d-4b0e-9e88-2c6c3d3a1b2c",
			ok:   true,
		},
		"mixed case": {
			cn:   "9e9A2f51-4C1d-4b0E-9e88-2C6c3D3a1B2c",
			want: "9e9a2f51-4c1d-4b0e-9e88-2c6c3d3a1b2c",
			ok:   true,
		},
		"not a guid": {cn: "not-a-guid"},
		"empty":      {cn: ""},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := &x509.Certificate{Subject: pkix.Name{CommonName: tc.cn}}
			got, ok := clientIDFromSubject(leaf)
			if ok != tc.ok {
				t.Fatalf("ok = %t, want %t", ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("clientID = %q, want %q", got, tc.want)
			}
		})
	}
}
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !windows || !amd64
// +build !windows !amd64

package attestation

import (
	"errors"
	"testing"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func TestUnsupportedPlatformFailsClosed(t *testing.T) {
	handle, err := defaultProvider.LoadAttestationLibrary()
	if handle != 0 {
		t.Fatalf("handle = %#x, want zero", handle)
	}
	if !errors.Is(err, managedidentity.ErrAttestationUnavailable) {
		t.Fatalf("error = %v, want it to wrap ErrAttestationUnavailable", err)
	}
}

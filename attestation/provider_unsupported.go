// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !windows || !amd64
// +build !windows !amd64

package attestation

import (
	"fmt"
	"runtime"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

type libraryProvider struct{}

func (*libraryProvider) LoadAttestationLibrary() (uintptr, error) {
	return 0, fmt.Errorf("%w: the embedded attestation library supports windows/amd64, not %s/%s",
		managedidentity.ErrAttestationUnavailable, runtime.GOOS, runtime.GOARCH)
}

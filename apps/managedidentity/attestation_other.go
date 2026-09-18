// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !windows

package managedidentity

import "fmt"

type unavailableAttestationProvider struct{}

func (unavailableAttestationProvider) LoadAttestationLibrary() (uintptr, error) {
	return 0, fmt.Errorf("%w: the native attestation library is available only on Windows", ErrAttestationUnavailable)
}

var defaultAttestationProvider AttestationProvider = unavailableAttestationProvider{}

// attestKeyGuard has no non-Windows implementation. KeyGuard is a Windows
// Virtualization Based Security feature and the native attestation library
// ships only for Windows, so every other platform reports the capability as
// absent.
func attestKeyGuard(endpoint, clientID string, key bindingKey, provider AttestationProvider) (string, error) {
	return "", fmt.Errorf("%w: KeyGuard attestation is available only on Windows", ErrAttestationUnavailable)
}

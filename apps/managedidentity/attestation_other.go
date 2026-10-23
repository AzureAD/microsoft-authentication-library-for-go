// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !windows

package managedidentity

// attestKeyGuard has no non-Windows implementation. KeyGuard is a Windows
// Virtualization Based Security feature and the native attestation library
// ships only for Windows, so every other platform reports the capability as
// absent.
func attestKeyGuard(endpoint, clientID string, key bindingKey) (string, error) {
	return "", ErrAttestationUnavailable
}

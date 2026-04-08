//go:build !windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import "crypto"

// GetOrCreateManagedIdentityKey is not supported on non-Windows platforms.
func GetOrCreateManagedIdentityKey(keyName string) (crypto.Signer, managedIdentityKeyType, error) {
	return nil, keyTypeInMemory, errMtlsPopWindowsOnly
}

// GetKeyGuardAttestationJWT is not supported on non-Windows platforms.
func GetKeyGuardAttestationJWT(s crypto.Signer, endpoint, clientID string) (string, error) {
	return "", errMtlsPopWindowsOnly
}

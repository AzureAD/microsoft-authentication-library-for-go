//go:build !windows

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import "crypto"

// GetOrCreateKeyGuardKey is not supported on non-Windows platforms.
func GetOrCreateKeyGuardKey(keyName string) (crypto.Signer, error) {
	return nil, errMtlsPopWindowsOnly
}

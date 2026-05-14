// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

// managedIdentityKeyType indicates which key storage tier was selected.
// Mirrors MSAL.NET's ManagedIdentityKeyType enum.
type managedIdentityKeyType int

const (
	// keyTypeKeyGuard: Software KSP + USER scope + VBS Virtual Isolation flags.
	// Requires Credential Guard / Core Isolation to be enabled on the VM.
	keyTypeKeyGuard managedIdentityKeyType = iota

	// keyTypeHardware: Software KSP + USER scope, no VBS flags.
	// Plain persisted CNG key — not hardware-backed by VBS.
	keyTypeHardware

	// keyTypeInMemory: RSA key generated in process memory (not persisted).
	// Used as a last-resort fallback when CNG key creation fails entirely.
	keyTypeInMemory
)

func (t managedIdentityKeyType) String() string {
	switch t {
	case keyTypeKeyGuard:
		return "KeyGuard"
	case keyTypeHardware:
		return "Hardware"
	case keyTypeInMemory:
		return "InMemory"
	default:
		return "Unknown"
	}
}

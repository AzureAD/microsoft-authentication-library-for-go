// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !windows

package managedidentity

// IMDSv2 binds a token to a key the host is able to isolate. Only Windows
// exposes such a key, through CNG's virtual isolation flag, so this build has
// no way to satisfy the requirement. Rather than fall back to a software key,
// which would produce a token that looks bound but is not, every request fails
// with ErrMtlsNotSupportedForPlatform.
//
// This mirrors MSAL .NET, which throws on any non-Windows platform.
type unsupportedKeyProvider struct{}

func (unsupportedKeyProvider) getOrCreateKey(string) (bindingKey, error) {
	return bindingKey{}, ErrMtlsNotSupportedForPlatform
}

func (unsupportedKeyProvider) deleteKey(string) error {
	return ErrMtlsNotSupportedForPlatform
}

// newKeyProvider returns a provider that refuses to mint a binding key.
func newKeyProvider() keyProvider { return unsupportedKeyProvider{} }

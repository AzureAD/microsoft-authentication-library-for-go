// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

type SamlTokenInfo struct {
	AssertionType string // Should be either constants SAMLV1Grant or SAMLV2Grant.
	Assertion     string
}

// TODO(jdoak): Remove this after integrating ops package.
func createSamlTokenInfo(assertionType, assertion string) SamlTokenInfo {
	return SamlTokenInfo{assertionType, assertion}
}

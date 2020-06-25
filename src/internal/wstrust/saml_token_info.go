// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

type SamlAssertionType int

const (
	SamlV1 SamlAssertionType = iota
	SamlV2
)

type SamlTokenInfo struct {
	AssertionType SamlAssertionType
	Assertion     string
}

func CreateSamlTokenInfo(assertionType SamlAssertionType, assertion string) *SamlTokenInfo {
	tokenInfo := &SamlTokenInfo{assertionType, assertion}
	return tokenInfo
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

type SamlAssertionType int

const (
	SamlV1 SamlAssertionType = iota
	SamlV2
)

type SamlTokenInfo struct {
	assertionType SamlAssertionType
	assertion     string
}

func CreateSamlTokenInfo(assertionType SamlAssertionType, assertion string) *SamlTokenInfo {
	tokenInfo := &SamlTokenInfo{assertionType, assertion}
	return tokenInfo
}

func (sti *SamlTokenInfo) GetAssertionType() SamlAssertionType {
	return sti.assertionType
}

func (sti *SamlTokenInfo) GetAssertion() string {
	return sti.assertion
}

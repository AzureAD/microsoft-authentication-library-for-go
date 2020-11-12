// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

type SamlAssertionType int

// TODO(msal reviewer): I love iota, but...  It is only safe if this value
// is never sent to another service or written to disk for retrieval. Otherwise
// the value should be statically assigned.  If someone can verify that.
// Also, I couldn't figure out why not just use msalbase.SAMLV1Grant... here
// instead of these values, instead we insert them in default_web_request_manager.go.
const (
	SamlV1 SamlAssertionType = iota
	SamlV2
)

type SamlTokenInfo struct {
	AssertionType SamlAssertionType
	Assertion     string
}

func createSamlTokenInfo(assertionType SamlAssertionType, assertion string) SamlTokenInfo {
	return SamlTokenInfo{assertionType, assertion}
}

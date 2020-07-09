// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type CredentialType int

const (
	CredentialTypeOauth2RefreshToken CredentialType = iota
	CredentialTypeOauth2AccessToken
	CredentialTypeOidcIDToken
	CredentialTypeOther
)

type Credential interface {
	CreateKey() string
	GetSecret() string
}

func (c CredentialType) ToString() string {
	switch c {
	case CredentialTypeOauth2AccessToken:
		return "AccessToken"
	case CredentialTypeOauth2RefreshToken:
		return "RefreshToken"
	case CredentialTypeOidcIDToken:
		return "IdToken"
	case CredentialTypeOther:
		return "Other"
	default:
		return ""
	}
}

func ToCredentialType(credTypeStr string) CredentialType {
	switch credTypeStr {
	case "AccessToken":
		return CredentialTypeOauth2AccessToken
	case "RefreshToken":
		return CredentialTypeOauth2RefreshToken
	case "IdToken":
		return CredentialTypeOidcIDToken
	default:
		return CredentialTypeOther
	}
}

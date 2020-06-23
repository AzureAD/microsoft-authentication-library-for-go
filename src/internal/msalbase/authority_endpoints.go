// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"fmt"
	"net/url"
)

type AuthorityEndpoints struct {
	authorizationEndpoint string
	tokenEndpoint         string
	selfSignedJwtAudience string
	authorityHost         string
}

func CreateAuthorityEndpoints(authorizationEndpoint string, tokenEndpoint string, selfSignedJwtAudience string, authorityHost string) *AuthorityEndpoints {
	return &AuthorityEndpoints{authorizationEndpoint, tokenEndpoint, selfSignedJwtAudience, authorityHost}
}

func (endpoints *AuthorityEndpoints) GetUserRealmEndpoint(username string) string {
	return fmt.Sprintf("https://%s/common/UserRealm/%s?api-version=1.0", endpoints.authorityHost, url.PathEscape(username))
}

func (endpoints *AuthorityEndpoints) GetTokenEndpoint() string {
	return endpoints.tokenEndpoint
}

func (endpoints *AuthorityEndpoints) GetAuthorizationEndpoint() string {
	return endpoints.authorizationEndpoint
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"fmt"
	"net/url"
)

//AuthorityEndpoints consists of the endpoints from the tenant discovery response
type AuthorityEndpoints struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	selfSignedJwtAudience string
	authorityHost         string
}

//CreateAuthorityEndpoints creates an AuthorityEndpoints object
func CreateAuthorityEndpoints(authorizationEndpoint string, tokenEndpoint string, selfSignedJwtAudience string, authorityHost string) *AuthorityEndpoints {
	return &AuthorityEndpoints{authorizationEndpoint, tokenEndpoint, selfSignedJwtAudience, authorityHost}
}

//GetUserRealmEndpoint returns the endpoint to get the user realm
func (endpoints *AuthorityEndpoints) GetUserRealmEndpoint(username string) string {
	return fmt.Sprintf("https://%s/common/UserRealm/%s?api-version=1.0", endpoints.authorityHost, url.PathEscape(username))
}

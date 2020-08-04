// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// UsernamePasswordRequest stuff
type UsernamePasswordRequest struct {
	webRequestManager WebRequestManager
	authParameters    *msalbase.AuthParametersInternal
}

// CreateUsernamePasswordRequest stuff
func CreateUsernamePasswordRequest(
	webRequestManager WebRequestManager,
	authParameters *msalbase.AuthParametersInternal) *UsernamePasswordRequest {
	req := &UsernamePasswordRequest{webRequestManager, authParameters}
	return req
}

// Execute stuff
func (req *UsernamePasswordRequest) Execute() (*msalbase.TokenResponse, error) {

	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}

	req.authParameters.Endpoints = endpoints

	userRealm, err := req.webRequestManager.GetUserRealm(req.authParameters)
	if err != nil {
		return nil, err
	}

	switch accountType := userRealm.GetAccountType(); accountType {
	case msalbase.Federated:
		if mexDoc, err := req.webRequestManager.GetMex(userRealm.FederationMetadataURL); err == nil {
			wsTrustEndpoint := mexDoc.UsernamePasswordEndpoint
			if wsTrustResponse, err := req.webRequestManager.GetWsTrustResponse(req.authParameters, userRealm.CloudAudienceURN, &wsTrustEndpoint); err == nil {
				if samlGrant, err := wsTrustResponse.GetSAMLAssertion(&wsTrustEndpoint); err == nil {
					return req.webRequestManager.GetAccessTokenFromSamlGrant(req.authParameters, samlGrant)
				}
			}
		}
		// todo: check for ui interaction in api result...
		return nil, err
	case msalbase.Managed:
		return req.webRequestManager.GetAccessTokenFromUsernamePassword(req.authParameters)
	default:
		return nil, errors.New("unknown account type")
	}
}

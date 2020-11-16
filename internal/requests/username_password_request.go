// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"context"
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// UsernamePasswordRequest stuff
type UsernamePasswordRequest struct {
	webRequestManager WebRequestManager
	authParameters    msalbase.AuthParametersInternal
}

// CreateUsernamePasswordRequest stuff
func CreateUsernamePasswordRequest(webRequestManager WebRequestManager, authParameters msalbase.AuthParametersInternal) *UsernamePasswordRequest {
	req := &UsernamePasswordRequest{webRequestManager, authParameters}
	return req
}

func (req *UsernamePasswordRequest) Execute(ctx context.Context) (msalbase.TokenResponse, error) {
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(ctx, req.authParameters.AuthorityInfo, "")
	if err != nil {
		return msalbase.TokenResponse{}, err
	}

	req.authParameters.Endpoints = endpoints

	userRealm, err := req.webRequestManager.GetUserRealm(ctx, req.authParameters)
	if err != nil {
		return msalbase.TokenResponse{}, err
	}

	switch accountType := userRealm.GetAccountType(); accountType {
	case msalbase.Federated:
		mexDoc, err := req.webRequestManager.GetMex(ctx, userRealm.FederationMetadataURL)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		wsTrustEndpoint := mexDoc.UsernamePasswordEndpoint
		wsTrustResponse, err := req.webRequestManager.GetWsTrustResponse(ctx, req.authParameters, userRealm.CloudAudienceURN, wsTrustEndpoint)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		samlGrant, err := wsTrustResponse.GetSAMLAssertion(wsTrustEndpoint)
		if err != nil {
			return msalbase.TokenResponse{}, err
		}
		return req.webRequestManager.GetAccessTokenFromSamlGrant(ctx, req.authParameters, samlGrant)
	case msalbase.Managed:
		return req.webRequestManager.GetAccessTokenFromUsernamePassword(ctx, req.authParameters)
	}
	return msalbase.TokenResponse{}, errors.New("unknown account type")
}

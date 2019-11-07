package requests

import (
	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/markzuber/msalgo/internal/msalbase"
)

// UsernamePasswordRequest stuff
type UsernamePasswordRequest struct {
	webRequestManager IWebRequestManager
	cacheManager      msalbase.ICacheManager
	authParameters    *msalbase.AuthParametersInternal
}

// CreateUsernamePasswordRequest stuff
func CreateUsernamePasswordRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal) *UsernamePasswordRequest {
	req := &UsernamePasswordRequest{webRequestManager, cacheManager, authParameters}
	return req
}

// Execute stuff
func (req *UsernamePasswordRequest) Execute() (*msalbase.TokenResponse, error) {

	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return nil, err
	}

	req.authParameters.SetAuthorityEndpoints(endpoints)

	userRealm, err := req.webRequestManager.GetUserRealm(req.authParameters)
	if err != nil {
		return nil, err
	}

	switch accountType := userRealm.GetAccountType(); accountType {
	case msalbase.Federated:
		log.Trace("FEDERATED")
		if mexDoc, err := req.webRequestManager.GetMex(userRealm.GetFederationMetadataURL()); err == nil {
			wsTrustEndpoint := mexDoc.GetWsTrustUsernamePasswordEndpoint()
			if wsTrustResponse, err := req.webRequestManager.GetWsTrustResponse(req.authParameters, userRealm.GetCloudAudienceURN(), &wsTrustEndpoint); err == nil {
				if samlGrant, err := wsTrustResponse.GetSAMLAssertion(&wsTrustEndpoint); err == nil {
					return req.webRequestManager.GetAccessTokenFromSamlGrant(req.authParameters, samlGrant)
				}
			}
		}
		// todo: check for ui interaction in api result...
		return nil, err
	case msalbase.Managed:
		log.Trace("MANAGED")
		return req.webRequestManager.GetAccessTokenFromUsernamePassword(req.authParameters)
	default:
		return nil, errors.New("Unknown account type")
	}
}

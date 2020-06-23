// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/requests"
)

// DeviceCodeRequest stuff
type deviceCodeRequest struct {
	webRequestManager  requests.IWebRequestManager
	cacheManager       msalbase.ICacheManager
	authParameters     *msalbase.AuthParametersInternal
	deviceCodeCallback func(IDeviceCodeResult)
	cancelCtx          context.Context
}

// CreateDeviceCodeRequest stuff
func createDeviceCodeRequest(cancelCtx context.Context,
	webRequestManager requests.IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal,
	deviceCodeCallback func(IDeviceCodeResult)) *deviceCodeRequest {
	req := &deviceCodeRequest{webRequestManager, cacheManager, authParameters, deviceCodeCallback, cancelCtx}
	return req
}

// Execute stuff
func (req *deviceCodeRequest) Execute() (*msalbase.TokenResponse, error) {
	// resolve authority endpoints
	resolutionManager := requests.CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return nil, err
	}

	req.authParameters.SetAuthorityEndpoints(endpoints)
	deviceCodeResult, err := req.webRequestManager.GetDeviceCodeResult(req.authParameters)
	if err != nil {
		return nil, err
	}
	// fire deviceCodeResult up to user
	log.Infof("%v", deviceCodeResult)
	req.deviceCodeCallback(deviceCodeResult)
	return req.waitForTokenResponse(deviceCodeResult)
}

func (req *deviceCodeRequest) waitForTokenResponse(deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error) {

	interval := deviceCodeResult.GetInterval()
	timeRemaining := deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())

	for timeRemaining.Seconds() > 0.0 {
		select {
		case <-req.cancelCtx.Done():
			return nil, errors.New("Token request canceled")
		default:
			tokenResponse, err := req.webRequestManager.GetAccessTokenFromDeviceCodeResult(req.authParameters, deviceCodeResult)
			if err != nil {
				if isErrorAuthorizationPending(err) {
					timeRemaining = deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())
				} else if isErrorSlowDown(err) {
					interval += msalbase.IntervalAddition
				} else {
					return nil, err
				}
			} else {
				return tokenResponse, nil
			}

			time.Sleep(time.Duration(interval) * time.Second)
		}
	}

	return nil, errors.New("Verification code expired before contacting the server")
}

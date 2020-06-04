// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"errors"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

// DeviceCodeRequest stuff
type DeviceCodeRequest struct {
	webRequestManager IWebRequestManager
	cacheManager      msalbase.ICacheManager
	authParameters    *msalbase.AuthParametersInternal
	deviceCodeResult  *msalbase.DeviceCodeResult
	cancelChannel     chan bool
}

// CreateDeviceCodeRequest stuff
func CreateDeviceCodeRequest(
	webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal,
	deviceCodeResult *msalbase.DeviceCodeResult, cancelChannel chan bool) *DeviceCodeRequest {
	req := &DeviceCodeRequest{webRequestManager, cacheManager, authParameters, deviceCodeResult, cancelChannel}
	return req
}

/*
func CreateDeviceCodeRequestWithDeviceCode(webRequestManager IWebRequestManager,
	cacheManager msalbase.ICacheManager,
	authParameters *msalbase.AuthParametersInternal, deviceCodeResult *msalbase.DeviceCodeResult) *DeviceCodeRequest {
	req := &DeviceCodeRequest{webRequestManager, cacheManager, authParameters, deviceCodeResult, false}
	return req
}*/

// Execute stuff
func (req *DeviceCodeRequest) Execute() (*msalbase.TokenResponse, error) {
	// resolve authority endpoints
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return nil, err
	}

	req.authParameters.SetAuthorityEndpoints(endpoints)
	deviceCodeResult, err := req.webRequestManager.GetDeviceCodeResult(req.authParameters)
	if err != nil {
		return nil, err
	}
	deviceCodeResult.CopyTo(req.deviceCodeResult)
	// fire deviceCodeResult up to user
	log.Infof("%v", req.deviceCodeResult)

	return req.waitForTokenResponse(req.deviceCodeResult)
}

func (req *DeviceCodeRequest) SetDeviceCodeResult() error {
	// resolve authority endpoints
	resolutionManager := CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.GetAuthorityInfo(), "")
	if err != nil {
		return err
	}
	req.authParameters.SetAuthorityEndpoints(endpoints)
	deviceCodeResult, err := req.webRequestManager.GetDeviceCodeResult(req.authParameters)
	if err != nil {
		return err
	}
	req.deviceCodeResult = deviceCodeResult
	return nil
}

func (req *DeviceCodeRequest) waitForTokenResponse(deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error) {

	interval := deviceCodeResult.GetInterval()
	timeRemaining := deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())

	for timeRemaining.Seconds() > 0.0 {
		// todo: how to check for cancellation requested...
		select {
		case cancel := <-req.cancelChannel:
			if cancel {
				return nil, errors.New("Token request canceled")
			}
		default:

		}
		// todo: learn more about go error handling so that this is managed through error flow and not parsing the token response...

		tokenResponse, err := req.webRequestManager.GetAccessTokenFromDeviceCodeResult(req.authParameters, deviceCodeResult)
		if err != nil {
			if isErrorAuthorizationPending(err) {
				timeRemaining = deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())
			} else if isErrorSlowDown(err) {
				interval += 5
			} else {
				return nil, err
			}
		} else {
			return tokenResponse, nil
		}

		time.Sleep(time.Duration(interval) * time.Second)
	}

	return nil, errors.New("Verification code expired before contacting the server")
}

func (req *DeviceCodeRequest) GetDeviceCodeResult() *msalbase.DeviceCodeResult {
	return req.deviceCodeResult
}

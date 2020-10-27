// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"context"
	"errors"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// deviceCodeRequest stores the values required to request a token from the authority using device code flow.
type deviceCodeRequest struct {
	webRequestManager  requests.WebRequestManager
	authParameters     *msalbase.AuthParametersInternal
	deviceCodeCallback func(DeviceCodeResultProvider)
	cancelCtx          context.Context
}

func createDeviceCodeRequest(cancelCtx context.Context,
	webRequestManager requests.WebRequestManager,
	authParameters *msalbase.AuthParametersInternal,
	deviceCodeCallback func(DeviceCodeResultProvider)) *deviceCodeRequest {
	req := &deviceCodeRequest{webRequestManager, authParameters, deviceCodeCallback, cancelCtx}
	return req
}

// Execute performs the token acquisition request and returns a token response or an error.
func (req *deviceCodeRequest) Execute() (*msalbase.TokenResponse, error) {
	// Resolve authority endpoints
	resolutionManager := requests.CreateAuthorityEndpointResolutionManager(req.webRequestManager)
	endpoints, err := resolutionManager.ResolveEndpoints(req.authParameters.AuthorityInfo, "")
	if err != nil {
		return nil, err
	}
	req.authParameters.Endpoints = endpoints
	deviceCodeResult, err := req.webRequestManager.GetDeviceCodeResult(req.authParameters)
	if err != nil {
		return nil, err
	}
	// Let the user do what they want with the device code result
	req.deviceCodeCallback(deviceCodeResult)
	// Using the device code to get the token response
	return req.waitForTokenResponse(deviceCodeResult)
}

func (req *deviceCodeRequest) waitForTokenResponse(deviceCodeResult *msalbase.DeviceCodeResult) (*msalbase.TokenResponse, error) {
	interval := deviceCodeResult.GetInterval()
	timeRemaining := deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())

	for timeRemaining.Seconds() > 0.0 {
		select {
		// If this request needs to be canceled, this context is used
		case <-req.cancelCtx.Done():
			return nil, errors.New("token request canceled")
		default:
			tokenResponse, err := req.webRequestManager.GetAccessTokenFromDeviceCodeResult(req.authParameters, deviceCodeResult)
			if err != nil {
				// If authorization is pending, update the time remaining
				if isErrorAuthorizationPending(err) {
					timeRemaining = deviceCodeResult.GetExpiresOn().Sub(time.Now().UTC())
					// If the device is polling too frequently, need to increase the polling interval
				} else if isErrorSlowDown(err) {
					interval += msalbase.IntervalAddition
				} else {
					return nil, err
				}
			} else {
				return tokenResponse, nil
			}
			// Making sure the polling happens at the correct interval
			time.Sleep(time.Duration(interval) * time.Second)
		}
	}
	return nil, errors.New("verification code expired before contacting the server")
}

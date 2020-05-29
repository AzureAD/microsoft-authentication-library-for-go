// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"encoding/json"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type deviceCodeResponse struct {
	BaseResponse    *msalbase.OAuthResponseBase
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// createDeviceCodeResponse stuff
func createDeviceCodeResponse(responseCode int, responseData string) (*deviceCodeResponse, error) {
	baseResponse, err := msalbase.CreateOAuthResponseBase(responseCode, responseData)
	if err != nil {
		return nil, err
	}

	dcResponse := &deviceCodeResponse{}
	err = json.Unmarshal([]byte(responseData), dcResponse)
	if err != nil {
		return nil, err
	}

	dcResponse.BaseResponse = baseResponse

	return dcResponse, nil
}

func (dcr *deviceCodeResponse) toDeviceCodeResult(clientID string, scopes []string) *msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.CreateDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

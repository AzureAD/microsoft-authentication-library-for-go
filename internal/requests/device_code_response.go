// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"encoding/json"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//DeviceCodeResponse represents the HTTP response received from the device code endpoint
type DeviceCodeResponse struct {
	BaseResponse    *msalbase.OAuthResponseBase
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

// CreateDeviceCodeResponse creates a deviceCodeResponse instance from HTTP response
func CreateDeviceCodeResponse(responseCode int, responseData string) (*DeviceCodeResponse, error) {
	baseResponse, err := msalbase.CreateOAuthResponseBase(responseCode, responseData)
	if err != nil {
		return nil, err
	}
	dcResponse := &DeviceCodeResponse{}
	err = json.Unmarshal([]byte(responseData), dcResponse)
	if err != nil {
		return nil, err
	}
	dcResponse.BaseResponse = baseResponse
	return dcResponse, nil
}

//ToDeviceCodeResult converts the DeviceCodeResponse to a DeviceCodeResult
func (dcr *DeviceCodeResponse) ToDeviceCodeResult(clientID string, scopes []string) *msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.CreateDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

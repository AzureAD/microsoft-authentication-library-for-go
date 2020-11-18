// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"io/ioutil"
	"net/http"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

//DeviceCodeResponse represents the HTTP response received from the device code endpoint
type DeviceCodeResponse struct {
	// TODO(jdoak): Ask someone about why BaseResponse doesn't have a tag.
	// Either it should be encoded and we should tag it or we should tag it
	// to be omitted on export or private.
	BaseResponse    msalbase.OAuthResponseBase
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`

	AdditionalFields map[string]interface{}
}

// CreateDeviceCodeResponse creates a deviceCodeResponse instance from HTTP response.
func CreateDeviceCodeResponse(resp *http.Response) (DeviceCodeResponse, error) {
	dcResponse := DeviceCodeResponse{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return dcResponse, err
	}
	baseResponse, err := msalbase.CreateOAuthResponseBase(resp.StatusCode, body)
	if err != nil {
		return dcResponse, err
	}

	if err := json.Unmarshal(body, &dcResponse); err != nil {
		return dcResponse, err
	}
	dcResponse.BaseResponse = baseResponse
	return dcResponse, nil
}

//ToDeviceCodeResult converts the DeviceCodeResponse to a DeviceCodeResult
func (dcr DeviceCodeResponse) ToDeviceCodeResult(clientID string, scopes []string) msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.CreateDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"reflect"
	"testing"
)

var expDevCodeResp = &deviceCodeResponse{
	UserCode:        "user",
	DeviceCode:      "dev",
	VerificationURL: "url",
	ExpiresIn:       10,
	Interval:        5,
	Message:         "message",
}

func TestCreateDeviceCodeResponse(t *testing.T) {
	dcrText := `{"user_code": "user", "device_code": "dev", "verification_url": "url",
				"expires_in": 10, "interval": 5, "message": "message"}`
	actualDCR, err := CreateDeviceCodeResponse(200, dcrText)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(expDevCodeResp.UserCode, actualDCR.UserCode) &&
		!reflect.DeepEqual(expDevCodeResp.DeviceCode, actualDCR.DeviceCode) &&
		!reflect.DeepEqual(expDevCodeResp.VerificationURL, actualDCR.VerificationURL) &&
		!reflect.DeepEqual(expDevCodeResp.ExpiresIn, actualDCR.ExpiresIn) &&
		!reflect.DeepEqual(expDevCodeResp.Interval, actualDCR.Interval) &&
		!reflect.DeepEqual(expDevCodeResp.Message, actualDCR.Message) {
		t.Errorf("Actual device code response %+v differs from expected device code response %+v", actualDCR, expDevCodeResp)
	}
}

func TestToDeviceCodeResult(t *testing.T) {}

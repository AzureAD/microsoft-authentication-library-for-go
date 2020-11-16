// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"fmt"
	"time"
)

// DeviceCodeResult stores the response from the STS device code endpoint.
type DeviceCodeResult struct {
	userCode        string
	deviceCode      string
	verificationURL string
	expiresOn       time.Time
	interval        int
	message         string
	clientID        string
	scopes          []string
}

// CreateDeviceCodeResult creates a DeviceCodeResult instance.
func CreateDeviceCodeResult(userCode, deviceCode, verificationURL string, expiresOn time.Time, interval int, message, clientID string, scopes []string) DeviceCodeResult {
	return DeviceCodeResult{userCode, deviceCode, verificationURL, expiresOn, interval, message, clientID, scopes}
}

func (dcr DeviceCodeResult) String() string {
	return fmt.Sprintf("UserCode: (%v)\nDeviceCode: (%v)\nURL: (%v)\nMessage: (%v)\n", dcr.userCode, dcr.deviceCode, dcr.verificationURL, dcr.message)

}

// GetUserCode returns the code the user needs to provide when authentication at the verification URI.
func (dcr DeviceCodeResult) GetUserCode() string {
	return dcr.userCode
}

// GetDeviceCode returns the code used in the access token request.
func (dcr DeviceCodeResult) GetDeviceCode() string {
	return dcr.deviceCode
}

// GetVerificationURL returns the URL where user can authenticate.
func (dcr DeviceCodeResult) GetVerificationURL() string {
	return dcr.verificationURL
}

// GetExpiresOn returns the expiration time of device code in seconds.
func (dcr DeviceCodeResult) GetExpiresOn() time.Time {
	return dcr.expiresOn
}

// GetInterval returns the interval at which the STS should be polled at.
func (dcr DeviceCodeResult) GetInterval() int {
	return dcr.interval
}

// GetMessage returns the message which should be displayed to the user.
func (dcr DeviceCodeResult) GetMessage() string {
	return dcr.message
}

// GetClientID returns the UUID issued by the authorization server for your application.
func (dcr DeviceCodeResult) GetClientID() string {
	return dcr.clientID
}

// GetScopes returns the scopes used to request access a protected API.
func (dcr DeviceCodeResult) GetScopes() []string {
	return dcr.scopes
}

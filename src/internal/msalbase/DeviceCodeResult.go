package msalbase

import (
	"fmt"
	"time"
)

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

func CreateDeviceCodeResult(userCode string, deviceCode string, verificationURL string, expiresOn time.Time, interval int, message string, clientID string, scopes []string) *DeviceCodeResult {
	return &DeviceCodeResult{userCode, deviceCode, verificationURL, expiresOn, interval, message, clientID, scopes}
}

func (r DeviceCodeResult) String() string {
	return fmt.Sprintf("UserCode: (%v)\nDeviceCode: (%v)\nURL: (%v)\nMessage: (%v)\n", r.GetUserCode(), r.GetDeviceCode(), r.GetVerificationURL(), r.GetMessage())

}

func (dcr *DeviceCodeResult) GetUserCode() string {
	return dcr.userCode
}

func (dcr *DeviceCodeResult) GetDeviceCode() string {
	return dcr.deviceCode
}

func (dcr *DeviceCodeResult) GetVerificationURL() string {
	return dcr.verificationURL
}

func (dcr *DeviceCodeResult) GetExpiresOn() time.Time {
	return dcr.expiresOn
}

func (dcr *DeviceCodeResult) GetInterval() int {
	return dcr.interval
}

func (dcr *DeviceCodeResult) GetMessage() string {
	return dcr.message
}

func (dcr *DeviceCodeResult) GetClientID() string {
	return dcr.clientID
}

func (dcr *DeviceCodeResult) GetScopes() []string {
	return dcr.scopes
}

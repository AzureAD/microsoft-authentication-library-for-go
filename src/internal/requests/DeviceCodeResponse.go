package requests

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/markzuber/msalgo/internal/msalbase"
)

type deviceCodeResponse struct {
	BaseResponse    *msalbase.OAuthResponseBase
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresInStr    string `json:"expires_in"`
	IntervalStr     string `json:"interval"`
	Message         string `json:"message"`

	ExpiresIn int
	Interval  int
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

	expiresIn, err := strconv.Atoi(dcResponse.ExpiresInStr)
	if err != nil {
		return nil, err
	}
	dcResponse.ExpiresIn = expiresIn

	interval, err := strconv.Atoi(dcResponse.IntervalStr)
	if err != nil {
		return nil, err
	}
	dcResponse.Interval = interval

	return dcResponse, nil
}

func (dcr *deviceCodeResponse) toDeviceCodeResult(clientID string, scopes []string) *msalbase.DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return msalbase.CreateDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"encoding/json"
	"errors"
)

//OAuthResponseBase stores common information when sending a request to get a token
type OAuthResponseBase struct {
	Error            string `json:"error"`
	SubError         string `json:"suberror"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	CorrelationID    string `json:"correlation_id"`
	Claims           string `json:"claims"`
}

var httpFailureCodes = map[int]string{
	404: "HTTP 404",
	500: "HTTP 500",
}

//CreateOAuthResponseBase creates a OAuthResponseBase instance from the HTTP client's response
func CreateOAuthResponseBase(httpStatusCode int, responseData string) (*OAuthResponseBase, error) {

	if failMessage, ok := httpFailureCodes[httpStatusCode]; ok {
		return nil, errors.New(failMessage)
	}

	payload := &OAuthResponseBase{}
	err := json.Unmarshal([]byte(responseData), payload)
	if err != nil {
		return nil, err
	}

	if payload.Error != "" {
		// todo: bring in error description, etc.
		return nil, errors.New(payload.Error)
	}
	return payload, nil
}

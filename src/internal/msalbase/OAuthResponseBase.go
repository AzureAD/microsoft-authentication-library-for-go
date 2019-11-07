package msalbase

import (
	"encoding/json"
	"errors"
)

type OAuthResponseBase struct {
	Error            string `json:"error"`
	SubError         string `json:"suberror"`
	ErrorDescription string `json:"error_description"`
	ErrorCodes       []int  `json:"error_codes"`
	CorrelationID    string `json:"correlation_id"`
	Claims           string `json:"claims"`
}

var httpFailureCodes = map[int]string{
	404: "HTTP 400",
	500: "HTTP 500",
}

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

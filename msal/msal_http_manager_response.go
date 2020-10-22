// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

import (
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
)

//msalHTTPManagerResponse is a wrapper for a http.Response
type msalHTTPManagerResponse struct {
	responseCode int
	responseData string
	headers      map[string]string
}

// GetResponseCode returns the response code of the HTTP reponse
func (r *msalHTTPManagerResponse) GetResponseCode() int {
	return r.responseCode
}

// GetResponseData returns the body of the HTTP response
func (r *msalHTTPManagerResponse) GetResponseData() string {
	return r.responseData
}

// GetHeaders returns the headers of the HTTP response
func (r *msalHTTPManagerResponse) GetHeaders() map[string]string {
	return r.headers
}

func createHTTPManagerResponse(resp *http.Response) (HTTPManagerResponse, error) {
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Info("   HTTP Response: " + resp.Status)
	log.Trace(string(body))

	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = v[0] // todo: broken?
	}
	r := &msalHTTPManagerResponse{responseCode: resp.StatusCode, responseData: string(body), headers: headers}
	return r, nil
}

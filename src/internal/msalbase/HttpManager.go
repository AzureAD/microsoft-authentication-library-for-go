// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// HTTPManager is a wrapper for http.Client
type HTTPManager struct {
	client *http.Client
}

// HTTPManagerResponse is a wrapper for a http.Response
type HTTPManagerResponse struct {
	responseCode int
	responseData string
	headers      map[string]string
}

// GetResponseCode returns the response code of the HTTP reponse
func (r *HTTPManagerResponse) GetResponseCode() int {
	return r.responseCode
}

// GetResponseData returns the body of the HTTP response
func (r *HTTPManagerResponse) GetResponseData() string {
	return r.responseData
}

// GetHeaders returns the headers of the HTTP response
func (r *HTTPManagerResponse) GetHeaders() map[string]string {
	return r.headers
}

// CreateHTTPManagerResponse wraps the http.Response object into a HTTPManagerResponse object
func CreateHTTPManagerResponse(resp *http.Response) (*HTTPManagerResponse, error) {

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

	r := &HTTPManagerResponse{responseCode: resp.StatusCode, responseData: string(body), headers: headers}
	return r, nil
}

// CreateHTTPManager creates a http.Client object and wraps it in a HTTPManager
func CreateHTTPManager() *HTTPManager {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext,
	}
	client := &http.Client{}
	client.Transport = tr
	mgr := &HTTPManager{client}
	return mgr
}

func (mgr *HTTPManager) performRequest(req *http.Request, requestHeaders map[string]string) (*HTTPManagerResponse, error) {
	log.Info("   HEADERS:")
	for k, v := range requestHeaders {
		req.Header.Add(k, v)
		log.Infof("     %v: %v", k, v)
	}

	resp, err := mgr.client.Do(req)
	if err != nil {
		return nil, err
	}

	return CreateHTTPManagerResponse(resp)
}

// Get stuff
func (mgr *HTTPManager) Get(url string, requestHeaders map[string]string) (*HTTPManagerResponse, error) {
	log.Info("<------------------")
	log.Infof("   GET to %v", url)
	defer log.Info("------------------>")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return mgr.performRequest(req, requestHeaders)
}

// Post stuff
func (mgr *HTTPManager) Post(url string, body string, requestHeaders map[string]string) (*HTTPManagerResponse, error) {
	log.Info("<------------------")
	log.Infof("   POST to %v", url)
	log.Trace(body)
	defer log.Info("------------------>")
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	return mgr.performRequest(req, requestHeaders)
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import (
	"net"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

//msalHTTPManager is a wrapper for http.Client
type msalHTTPManager struct {
	client *http.Client
}

// CreateHTTPManager creates a http.Client object and wraps it in a msalHTTPManager
func createHTTPManager() HTTPManager {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext,
	}
	client := &http.Client{}
	client.Transport = tr
	mgr := &msalHTTPManager{client}
	return mgr
}

func (mgr *msalHTTPManager) performRequest(
	req *http.Request, requestHeaders map[string]string) (HTTPManagerResponse, error) {
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

// Get sends a get request to the appropriate URL
func (mgr *msalHTTPManager) Get(url string, requestHeaders map[string]string) (HTTPManagerResponse, error) {
	log.Info("<------------------")
	log.Infof("   GET to %v", url)
	defer log.Info("------------------>")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return mgr.performRequest(req, requestHeaders)
}

// Post sends a post request to the appropriate URL
func (mgr *msalHTTPManager) Post(url string, body string, requestHeaders map[string]string) (HTTPManagerResponse, error) {
	log.Info("<------------------")
	log.Infof("   POST to %v", url)
	log.Info(body)
	defer log.Info("------------------>")
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	return mgr.performRequest(req, requestHeaders)
}

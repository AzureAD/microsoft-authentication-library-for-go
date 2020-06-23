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

// HTTPManager is a wrapper for http.Client
type HTTPManager struct {
	client *http.Client
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
func (mgr *HTTPManager) Get(url string, requestHeaders map[string]string) (IHTTPManagerResponse, error) {
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
func (mgr *HTTPManager) Post(url string, body string, requestHeaders map[string]string) (IHTTPManagerResponse, error) {
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

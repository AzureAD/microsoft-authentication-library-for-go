// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package mock

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Client is a mock HTTP client that returns a sequence of responses. Use AppendResponse to specify the sequence.
type SyncClient struct {
	mu   sync.Mutex
	resp []response
}

func (c *SyncClient) AppendResponse(opts ...responseOption) {
	c.mu.Lock()
	defer c.mu.Unlock()

	r := response{code: http.StatusOK, headers: http.Header{}}
	for _, o := range opts {
		o.apply(&r)
	}
	c.resp = append(c.resp, r)
}

func (c *SyncClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.resp) == 0 {
		panic(fmt.Sprintf(`no response for "%s"`, req.URL.String()))
	}
	resp := c.resp[0]
	c.resp = c.resp[1:]
	if resp.callback != nil {
		resp.callback(req)
	}
	res := http.Response{Header: resp.headers, StatusCode: resp.code}
	res.Body = io.NopCloser(bytes.NewReader(resp.body))
	return &res, nil
}

// CloseIdleConnections implements the comm.HTTPClient interface
func (*SyncClient) CloseIdleConnections() {}

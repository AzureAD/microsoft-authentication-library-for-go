// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/tls"
	"net/http"
)

// NewMtlsHTTPClient creates an *http.Client configured for mutual TLS (mTLS)
// using the provided client certificate. The certificate is presented during
// the TLS handshake to authenticate the client to the server.
// This is used by the mTLS Proof of Possession (RFC 8705) token acquisition flow.
func NewMtlsHTTPClient(cert tls.Certificate) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
	}
}

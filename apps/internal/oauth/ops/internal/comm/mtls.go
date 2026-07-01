// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
)

// MtlsClientFactory optionally builds an HTTPClient whose transport presents cert as the client
// certificate during the mutual-TLS handshake. It is the documented override hook
// (confidential.WithMtlsHTTPClient) for callers whose keys cannot be used by the built-in transport
// (for example CNG/HSM-backed keys). When unset, MSAL auto-builds and caches a client per certificate.
type MtlsClientFactory func(cert tls.Certificate) HTTPClient

// SetMtlsClientFactory installs a custom factory for building mTLS clients. It must be called during
// construction, before any concurrent token calls.
func (c *Client) SetMtlsClientFactory(factory MtlsClientFactory) {
	c.mtlsFactory = factory
}

// BuildMtlsClient returns an *http.Client whose transport presents cert as the client certificate
// during the TLS handshake. It clones http.DefaultTransport so default proxy/dial behavior is
// preserved and enforces a TLS 1.2 minimum.
func BuildMtlsClient(cert tls.Certificate) *http.Client {
	var transport *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	return &http.Client{Transport: transport}
}

// mtlsClient returns an HTTPClient bound to cert, building and caching one per certificate thumbprint
// so repeated mTLS PoP calls reuse the same connection pool.
func (c *Client) mtlsClient(cert *tls.Certificate) (HTTPClient, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("mTLS proof-of-possession requires a binding certificate")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	key := base64.RawURLEncoding.EncodeToString(sum[:])

	c.mtlsMu.Lock()
	defer c.mtlsMu.Unlock()
	if c.mtlsClients == nil {
		c.mtlsClients = map[string]HTTPClient{}
	}
	if existing, ok := c.mtlsClients[key]; ok {
		return existing, nil
	}
	var client HTTPClient
	if c.mtlsFactory != nil {
		client = c.mtlsFactory(*cert)
	} else {
		client = BuildMtlsClient(*cert)
	}
	c.mtlsClients[key] = client
	return client, nil
}

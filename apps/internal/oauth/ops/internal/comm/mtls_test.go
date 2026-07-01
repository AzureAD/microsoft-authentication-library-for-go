// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestBuildMtlsClient(t *testing.T) {
	cert := tls.Certificate{Certificate: [][]byte{{0x01, 0x02, 0x03}}}
	client := BuildMtlsClient(cert)
	if client == nil {
		t.Fatal("BuildMtlsClient returned nil")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client.Transport = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}
	if got := len(transport.TLSClientConfig.Certificates); got != 1 {
		t.Fatalf("TLSClientConfig.Certificates has %d entries, want 1", got)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestMtlsClientCachePerThumbprint(t *testing.T) {
	certA := &tls.Certificate{Certificate: [][]byte{{0xAA, 0xBB}}}
	certB := &tls.Certificate{Certificate: [][]byte{{0xCC, 0xDD}}}

	var built int
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient {
		built++
		return &http.Client{}
	})

	first, err := c.mtlsClient(certA)
	if err != nil {
		t.Fatalf("mtlsClient(certA) error: %v", err)
	}
	second, err := c.mtlsClient(certA)
	if err != nil {
		t.Fatalf("mtlsClient(certA) second call error: %v", err)
	}
	if first != second {
		t.Error("expected the same cached client for the same certificate thumbprint")
	}
	if built != 1 {
		t.Errorf("factory called %d times for the same cert, want 1", built)
	}

	if _, err := c.mtlsClient(certB); err != nil {
		t.Fatalf("mtlsClient(certB) error: %v", err)
	}
	if built != 2 {
		t.Errorf("factory called %d times total, want 2 (one per distinct cert)", built)
	}
}

func TestMtlsClientRequiresCert(t *testing.T) {
	c := &Client{}
	if _, err := c.mtlsClient(nil); err == nil {
		t.Error("mtlsClient(nil) = nil error, want error")
	}
	if _, err := c.mtlsClient(&tls.Certificate{}); err == nil {
		t.Error("mtlsClient(empty) = nil error, want error")
	}
}

func TestMtlsClientUsesFactoryOverride(t *testing.T) {
	cert := &tls.Certificate{Certificate: [][]byte{{0x11}}}
	sentinel := &http.Client{}
	c := &Client{}
	c.SetMtlsClientFactory(func(tls.Certificate) HTTPClient { return sentinel })

	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatalf("mtlsClient error: %v", err)
	}
	if got != sentinel {
		t.Error("mtlsClient did not return the client produced by the override factory")
	}
}

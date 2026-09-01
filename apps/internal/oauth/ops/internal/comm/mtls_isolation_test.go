// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package comm

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
)

// notATransport is an http.RoundTripper that is not an *http.Transport, used to stand in for the
// wrappers tracing, proxy-injection and test libraries install.
type notATransport struct{}

func (notATransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, nil
}

// TestBuildMtlsClientLeavesNilSessionCacheNil pins the asymmetry in how the session cache is handled.
//
// A shared non-nil cache must be replaced, because tls.Config.Clone shallow-copies the interface and
// a client holding certificate B could otherwise resume a session the server authenticated under
// certificate A. A nil cache must be left alone: there is no object to share, so nothing can leak,
// and crypto/tls reads nil as "no session resumption". Installing a cache there would opt a caller
// who deliberately disabled resumption back into it on the mTLS leg -- MSAL quietly re-enabling a
// TLS feature the caller turned off.
func TestBuildMtlsClientLeavesNilSessionCacheNil(t *testing.T) {
	cert := signerOnlyTestCert(t)

	t.Run("nil stays nil", func(t *testing.T) {
		base := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}}
		client, err := BuildMtlsClient(cert, base)
		if err != nil {
			t.Fatal(err)
		}
		got := client.Transport.(*http.Transport).TLSClientConfig.ClientSessionCache
		if got != nil {
			t.Error("a caller who disabled session resumption had it re-enabled on the mTLS leg")
		}
	})

	t.Run("shared cache is replaced", func(t *testing.T) {
		shared := tls.NewLRUClientSessionCache(0)
		base := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				ClientSessionCache: shared,
			},
		}}
		client, err := BuildMtlsClient(cert, base)
		if err != nil {
			t.Fatal(err)
		}
		got := client.Transport.(*http.Transport).TLSClientConfig.ClientSessionCache
		if got == nil {
			t.Fatal("a configured session cache was dropped entirely")
		}
		if got == shared {
			t.Error("the mTLS client shares the caller's session cache, so a client bound to one certificate could resume a session authenticated under another")
		}
	})
}

// TestCloneBaseTransportFailsClosedOnReplacedDefaultTransport proves the last resort is an error, not
// a bare &http.Transport{}.
//
// Falling back looks harmless because a fresh transport cannot carry a dial hook, but it discards
// whatever the replacement enforces -- proxy routing, certificate pinning, auditing, egress control
// -- for a request that carries a client credential. It is the same failure the two caller-supplied
// branches already refuse, and a bare transport additionally has no Proxy function, so it ignores
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY.
func TestCloneBaseTransportFailsClosedOnReplacedDefaultTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	http.DefaultTransport = notATransport{}

	_, err := cloneBaseTransport(nil)
	if err == nil {
		t.Fatal("cloneBaseTransport silently substituted a bare transport for a replaced http.DefaultTransport")
	}
	for _, want := range []string{"http.DefaultTransport", "NO_PROXY", "WithMtlsHTTPClient"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q so the caller can act on it, got: %v", want, err)
		}
	}

	// BuildMtlsClient must surface it rather than swallow it.
	if _, err := BuildMtlsClient(signerOnlyTestCert(t), nil); err == nil {
		t.Error("BuildMtlsClient returned a client built on a transport it could not validate")
	}
}

// TestCloneBaseTransportStillWorksWithRealDefaultTransport guards the guard: the fail-closed branch
// must not fire in the ordinary case, where http.DefaultTransport is untouched.
func TestCloneBaseTransportStillWorksWithRealDefaultTransport(t *testing.T) {
	got, err := cloneBaseTransport(nil)
	if err != nil {
		t.Fatalf("cloneBaseTransport rejected an unmodified http.DefaultTransport: %v", err)
	}
	if got == nil {
		t.Fatal("expected a cloned transport")
	}
	if got == http.DefaultTransport {
		t.Error("expected a clone, not http.DefaultTransport itself")
	}
	if got.Proxy == nil {
		t.Error("the clone lost http.DefaultTransport's Proxy function, so it ignores HTTP_PROXY/HTTPS_PROXY/NO_PROXY")
	}
}

// TestMtlsClientPinsCertificateDER proves the cache key and the bytes that reach the handshake come
// from one private snapshot.
//
// The key is a digest of Certificate[0], and the certificate is then passed by value to the factory
// or to BuildMtlsClient -- a shallow copy sharing the caller's backing arrays. Anything still holding
// those arrays could rewrite them after the key was computed, leaving a cached client presenting
// bytes that no longer match the thumbprint it is filed under, and a token bound to a certificate
// MSAL never saw.
func TestMtlsClientPinsCertificateDER(t *testing.T) {
	der := []byte{0x01, 0x02, 0x03, 0x04}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: testKey}

	var seen []byte
	c := &Client{}
	c.SetMtlsClientFactory(func(got tls.Certificate) HTTPClient {
		// Retain what the factory was handed, exactly as a factory building a long-lived client would.
		seen = got.Certificate[0]
		return &http.Client{}
	})

	if _, err := c.mtlsClient(cert); err != nil {
		t.Fatal(err)
	}
	if seen == nil {
		t.Fatal("factory was not called")
	}
	if &seen[0] == &der[0] {
		t.Fatal("the factory was handed the caller's backing array, so the certificate MSAL presents is still caller-mutable after the cache key was computed")
	}

	before := append([]byte(nil), seen...)
	for i := range der {
		der[i] ^= 0xff
	}
	if !bytes.Equal(seen, before) {
		t.Error("mutating the caller's DER changed the certificate the cached client presents, so it no longer matches the thumbprint it is filed under")
	}
}

// TestMtlsClientPinnedCertReachesBuiltClient covers the same isolation on the default path, where
// there is no factory and BuildMtlsClient constructs the client.
func TestMtlsClientPinnedCertReachesBuiltClient(t *testing.T) {
	tlsCert := signerOnlyTestCert(t)
	der := tlsCert.Certificate[0]
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: tlsCert.PrivateKey}

	c := &Client{}
	got, err := c.mtlsClient(cert)
	if err != nil {
		t.Fatal(err)
	}
	presented := got.(*http.Client).Transport.(*http.Transport).TLSClientConfig.Certificates[0].Certificate[0]
	if &presented[0] == &der[0] {
		t.Fatal("the built client presents the caller's backing array")
	}
	before := append([]byte(nil), presented...)
	for i := range der {
		der[i] ^= 0xff
	}
	if !bytes.Equal(presented, before) {
		t.Error("mutating the caller's DER changed what the cached client presents on the handshake")
	}
}

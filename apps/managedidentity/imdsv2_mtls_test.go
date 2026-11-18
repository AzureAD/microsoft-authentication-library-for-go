// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// testMtlsFactoryClient is the HTTP client passed to WithHTTPClient in IMDSv2
// tests. It handles metadata requests through client and creates a fresh
// configurable adapter for each certificate cache miss.
type testMtlsFactoryClient struct {
	client    ops.HTTPClient
	newClient func() (ClientConfigurer, error)
}

func (c *testMtlsFactoryClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}

func (c *testMtlsFactoryClient) CloseIdleConnections() {
	c.client.CloseIdleConnections()
}

func (c *testMtlsFactoryClient) NewMtlsClient() (ClientConfigurer, error) {
	return c.newClient()
}

// testClientConfigurer is a minimal middleware adapter. ConfigureClient keeps
// the augmented child, and Do and CloseIdleConnections continue to traverse
// this adapter so tests can verify middleware preservation and cleanup.
type testClientConfigurer struct {
	base           *http.Client
	configure      func(func(*http.Client) (*http.Client, error)) error
	mu             sync.RWMutex
	client         *http.Client
	doCalls        atomic.Int32
	closeIdleCalls atomic.Int32
}

func (c *testClientConfigurer) ConfigureClient(
	augment func(*http.Client) (*http.Client, error),
) error {
	if c.configure != nil {
		return c.configure(augment)
	}
	client, err := augment(c.base)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.client = client
	c.mu.Unlock()
	return nil
}

func (c *testClientConfigurer) Do(req *http.Request) (*http.Response, error) {
	c.doCalls.Add(1)
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()
	if client == nil {
		return nil, errors.New("test ClientConfigurer was used before configuration")
	}
	return client.Do(req)
}

func (c *testClientConfigurer) CloseIdleConnections() {
	c.closeIdleCalls.Add(1)
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()
	if client != nil {
		client.CloseIdleConnections()
	}
}

func (c *testClientConfigurer) configuredClient() *http.Client {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

type closeTrackingHTTPClient struct {
	closeIdleCalls atomic.Int32
}

func (*closeTrackingHTTPClient) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected request")
}

func (c *closeTrackingHTTPClient) CloseIdleConnections() {
	c.closeIdleCalls.Add(1)
}

type testCookieJar struct{}

func (*testCookieJar) SetCookies(*url.URL, []*http.Cookie) {}
func (*testCookieJar) Cookies(*url.URL) []*http.Cookie     { return nil }

func TestIMDSv2MtlsFactoryContractFailsClosed(t *testing.T) {
	binding := testBindingFromTLSCertificate(t, selfSignedTLSCertificate(t))
	factoryErr := errors.New("factory failed")
	configurerErr := errors.New("configurer failed")

	type state struct {
		adapter    *testClientConfigurer
		augmentErr error
		late       func(*http.Client) (*http.Client, error)
	}
	tests := []struct {
		name              string
		newClient         func(*state) (ClientConfigurer, error)
		want              []string
		wantFactoryErr    bool
		wantConfigurerErr bool
		wantAugmentErr    bool
		invokeLate        bool
	}{
		{
			name: "no augment call",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(func(*http.Client) (*http.Client, error)) error { return nil },
				}
				return s.adapter, nil
			},
			want: []string{"exactly once", "got 0 calls"},
		},
		{
			name: "multiple augment calls",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(augment func(*http.Client) (*http.Client, error)) error {
						_, _ = augment(&http.Client{})
						_, _ = augment(&http.Client{})
						return nil
					},
				}
				return s.adapter, nil
			},
			want: []string{"called augment 2 times", "exactly once"},
		},
		{
			name: "nil base",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(augment func(*http.Client) (*http.Client, error)) error {
						_, _ = augment(nil)
						return nil
					},
				}
				return s.adapter, nil
			},
			want: []string{"nil base *http.Client"},
		},
		{
			name: "nil result",
			newClient: func(*state) (ClientConfigurer, error) {
				return nil, nil
			},
			want: []string{"returned a nil ClientConfigurer"},
		},
		{
			name: "factory error",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{base: &http.Client{}}
				return s.adapter, factoryErr
			},
			want:           []string{"factory failed"},
			wantFactoryErr: true,
		},
		{
			name: "configurer error",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(augment func(*http.Client) (*http.Client, error)) error {
						_, _ = augment(&http.Client{})
						return configurerErr
					},
				}
				return s.adapter, nil
			},
			want:              []string{"ConfigureClient failed", "configurer failed"},
			wantConfigurerErr: true,
		},
		{
			name: "swallowed augmentation error",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(augment func(*http.Client) (*http.Client, error)) error {
						_, s.augmentErr = augment(&http.Client{
							Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
								return nil, errors.New("unused")
							}),
						})
						return nil
					},
				}
				return s.adapter, nil
			},
			want:           []string{"cannot be installed"},
			wantAugmentErr: true,
		},
		{
			name: "configurer and augmentation errors",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(augment func(*http.Client) (*http.Client, error)) error {
						_, s.augmentErr = augment(nil)
						return configurerErr
					},
				}
				return s.adapter, nil
			},
			want:              []string{"nil base *http.Client", "configurer failed"},
			wantConfigurerErr: true,
			wantAugmentErr:    true,
		},
		{
			name: "late augment call",
			newClient: func(s *state) (ClientConfigurer, error) {
				s.adapter = &testClientConfigurer{
					configure: func(augment func(*http.Client) (*http.Client, error)) error {
						s.late = augment
						return nil
					},
				}
				return s.adapter, nil
			},
			want:       []string{"exactly once", "got 0 calls"},
			invokeLate: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &state{}
			factory := &testMtlsFactoryClient{
				client:    &http.Client{},
				newClient: func() (ClientConfigurer, error) { return test.newClient(state) },
			}
			client := Client{httpClient: factory, mtlsClients: newIMDSv2MtlsClientCache()}

			_, err := client.mtlsClient(binding)
			if err == nil {
				t.Fatal("factory contract violation succeeded")
			}
			for _, want := range test.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want text %q", err, want)
				}
			}
			if test.wantFactoryErr && !errors.Is(err, factoryErr) {
				t.Errorf("error %v doesn't preserve factory error %v", err, factoryErr)
			}
			if test.wantConfigurerErr && !errors.Is(err, configurerErr) {
				t.Errorf("error %v doesn't preserve configurer error %v", err, configurerErr)
			}
			if test.wantAugmentErr && !errors.Is(err, state.augmentErr) {
				t.Errorf("error %v doesn't preserve augmentation error %v", err, state.augmentErr)
			}
			if test.invokeLate {
				if state.late == nil {
					t.Fatal("ConfigureClient didn't retain augment for the late-call assertion")
				}
				if _, lateErr := state.late(&http.Client{}); lateErr == nil ||
					!strings.Contains(lateErr.Error(), "after ConfigureClient returned") {
					t.Errorf("late augment error = %v, want ConfigureClient timing error", lateErr)
				}
			}
			if state.adapter != nil && state.adapter.closeIdleCalls.Load() != 0 {
				t.Fatal("a failed configuration closed the adapter instead of only its private child")
			}
		})
	}
}

func TestIMDSv2MtlsAugmenterPreservesApplicationClient(t *testing.T) {
	binding := testBindingFromTLSCertificate(t, selfSignedTLSCertificate(t))
	proxyURL, err := url.Parse("http://proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	proxy := func(*http.Request) (*url.URL, error) { return proxyURL, nil }
	dialErr := errors.New("application dialer called")
	dialer := func(context.Context, string, string) (net.Conn, error) { return nil, dialErr }
	roots := x509.NewCertPool()
	sharedSessions := tls.NewLRUClientSessionCache(4)
	originalCertificate := selfSignedTLSCertificate(t)
	originalGetCertificate := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &originalCertificate, nil
	}
	transport := &http.Transport{
		Proxy:                 proxy,
		DialContext:           dialer,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          37,
		MaxIdleConnsPerHost:   11,
		MaxConnsPerHost:       13,
		IdleConnTimeout:       19 * time.Second,
		TLSHandshakeTimeout:   23 * time.Second,
		ResponseHeaderTimeout: 29 * time.Second,
		TLSClientConfig: &tls.Config{ //nolint:gosec // verifies the augmenter raises an insecure caller floor
			MinVersion:           tls.VersionTLS10,
			RootCAs:              roots,
			Certificates:         []tls.Certificate{originalCertificate},
			GetClientCertificate: originalGetCertificate,
			ClientSessionCache:   sharedSessions,
		},
	}
	jar := &testCookieJar{}
	base := &http.Client{Transport: transport, Timeout: 31 * time.Second, Jar: jar}
	adapter := &testClientConfigurer{base: base}
	factory := &testMtlsFactoryClient{
		client:    &closeTrackingHTTPClient{},
		newClient: func() (ClientConfigurer, error) { return adapter, nil },
	}
	client := Client{httpClient: factory, mtlsClients: newIMDSv2MtlsClientCache()}

	got, err := client.mtlsClient(binding)
	if err != nil {
		t.Fatal(err)
	}
	if got != adapter {
		t.Fatalf("mtlsClient returned %T, want the middleware adapter", got)
	}
	configured := adapter.configuredClient()
	if configured == nil || configured == base {
		t.Fatal("augmenter didn't install a private client copy")
	}
	cloned, ok := configured.Transport.(*http.Transport)
	if !ok || cloned == transport {
		t.Fatalf("configured Transport = %T, want a private *http.Transport clone", configured.Transport)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	gotProxy, err := cloned.Proxy(req)
	if err != nil || gotProxy.String() != proxyURL.String() {
		t.Fatalf("proxy = %v, %v; want %v", gotProxy, err, proxyURL)
	}
	if _, err := cloned.DialContext(context.Background(), "tcp", "example.invalid:443"); !errors.Is(err, dialErr) {
		t.Fatalf("DialContext error = %v, want %v", err, dialErr)
	}
	if cloned.TLSClientConfig.RootCAs != roots {
		t.Fatal("configured transport didn't preserve application trust roots")
	}
	if configured.Timeout != base.Timeout || configured.Jar != jar ||
		cloned.ForceAttemptHTTP2 != transport.ForceAttemptHTTP2 ||
		cloned.MaxIdleConns != transport.MaxIdleConns ||
		cloned.MaxIdleConnsPerHost != transport.MaxIdleConnsPerHost ||
		cloned.MaxConnsPerHost != transport.MaxConnsPerHost ||
		cloned.IdleConnTimeout != transport.IdleConnTimeout ||
		cloned.TLSHandshakeTimeout != transport.TLSHandshakeTimeout ||
		cloned.ResponseHeaderTimeout != transport.ResponseHeaderTimeout {
		t.Fatal("configured client didn't preserve timeout or connection-pool policy")
	}
	if cloned.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS minimum = %x, want TLS 1.2", cloned.TLSClientConfig.MinVersion)
	}
	if len(cloned.TLSClientConfig.Certificates) != 0 || cloned.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("MSAL didn't take ownership of certificate selection on the clone")
	}
	installed, err := cloned.TLSClientConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if installed == nil || len(installed.Certificate) == 0 {
		t.Fatal("configured transport has no binding certificate")
	}
	if &installed.Certificate[0][0] == &binding.TLS.Certificate[0][0] {
		t.Fatal("configured transport retained the cached certificate's DER backing array")
	}
	if _, ok := installed.PrivateKey.(*retainedSigner); !ok {
		t.Fatalf("configured private key = %T, want a retained signer", installed.PrivateKey)
	}
	if cloned.TLSClientConfig.ClientSessionCache == nil ||
		cloned.TLSClientConfig.ClientSessionCache == sharedSessions {
		t.Fatal("configured transport shares application TLS session state")
	}
	if configured.CheckRedirect == nil {
		t.Fatal("configured client has no redirect refusal")
	}

	// The caller's base remains byte-for-byte policy-equivalent.
	if base.Transport != transport || base.CheckRedirect != nil || base.Timeout != 31*time.Second {
		t.Fatal("augmenter mutated the application client")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS10 ||
		transport.TLSClientConfig.RootCAs != roots ||
		transport.TLSClientConfig.ClientSessionCache != sharedSessions ||
		len(transport.TLSClientConfig.Certificates) != 1 ||
		reflect.ValueOf(transport.TLSClientConfig.GetClientCertificate).Pointer() != reflect.ValueOf(originalGetCertificate).Pointer() {
		t.Fatal("augmenter mutated the application transport or TLS configuration")
	}

	_, err = got.Do(req)
	if !errors.Is(err, dialErr) {
		t.Fatalf("adapter Do error = %v, want the preserved dialer error", err)
	}
	if adapter.doCalls.Load() != 1 {
		t.Fatal("request bypassed the configured middleware adapter")
	}
}

func TestIMDSv2MtlsClientsIsolatePoolsAndSessions(t *testing.T) {
	sharedSessions := tls.NewLRUClientSessionCache(2)
	baseTransport := &http.Transport{TLSClientConfig: &tls.Config{ClientSessionCache: sharedSessions}}
	base := &http.Client{Transport: baseTransport}
	var adapters []*testClientConfigurer
	factory := &testMtlsFactoryClient{
		client: &http.Client{},
		newClient: func() (ClientConfigurer, error) {
			adapter := &testClientConfigurer{base: base}
			adapters = append(adapters, adapter)
			return adapter, nil
		},
	}
	client := Client{httpClient: factory, mtlsClients: newIMDSv2MtlsClientCache()}

	first, err := client.mtlsClient(testBindingFromTLSCertificate(t, selfSignedTLSCertificate(t)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.mtlsClient(testBindingFromTLSCertificate(t, selfSignedTLSCertificate(t)))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(adapters) != 2 {
		t.Fatal("different certificates didn't receive independent adapters")
	}
	firstTransport := adapters[0].configuredClient().Transport.(*http.Transport)
	secondTransport := adapters[1].configuredClient().Transport.(*http.Transport)
	if firstTransport == secondTransport {
		t.Fatal("different certificates shared a connection pool")
	}
	firstSessions := firstTransport.TLSClientConfig.ClientSessionCache
	secondSessions := secondTransport.TLSClientConfig.ClientSessionCache
	if firstSessions == nil || secondSessions == nil ||
		firstSessions == sharedSessions || secondSessions == sharedSessions ||
		firstSessions == secondSessions {
		t.Fatal("different certificates shared TLS session state")
	}
	if base.Transport != baseTransport ||
		baseTransport.TLSClientConfig.ClientSessionCache != sharedSessions {
		t.Fatal("configuration mutated the shared base transport")
	}
}

func TestIMDSv2MtlsFailsClosedForUnaugmentableTransports(t *testing.T) {
	binding := testBindingFromTLSCertificate(t, selfSignedTLSCertificate(t))
	tests := []struct {
		name string
		base ops.HTTPClient
		want string
	}{
		{
			name: "opaque HTTP client",
			base: stubHTTPClient(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("unused")
			}),
			want: "does not implement managedidentity.MtlsHTTPClientFactory",
		},
		{
			name: "opaque RoundTripper",
			base: &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("unused")
			})},
			want: "cannot be installed",
		},
		{
			name: "TLS dial hook",
			base: &http.Client{Transport: &http.Transport{
				DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("unused")
				},
			}},
			want: "DialTLSContext",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := Client{httpClient: test.base, mtlsClients: newIMDSv2MtlsClientCache()}
			if _, err := client.mtlsClient(binding); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("mtlsClient error = %v, want text %q", err, test.want)
			}
		})
	}
}

func TestIMDSv2MtlsCacheClosesEvictedChildrenNotTheFactory(t *testing.T) {
	original := &closeTrackingHTTPClient{}
	var adapters []*testClientConfigurer
	factory := &testMtlsFactoryClient{
		client: original,
		newClient: func() (ClientConfigurer, error) {
			adapter := &testClientConfigurer{base: &http.Client{}}
			adapters = append(adapters, adapter)
			return adapter, nil
		},
	}
	client := Client{httpClient: factory, mtlsClients: newIMDSv2MtlsClientCache()}

	for i := 0; i < mtlsClientCacheLimit+1; i++ {
		binding := testBindingFromTLSCertificate(t, selfSignedTLSCertificate(t))
		if _, err := client.mtlsClient(binding); err != nil {
			t.Fatalf("mtlsClient %d: %v", i, err)
		}
	}

	closed := int32(0)
	for _, adapter := range adapters {
		closed += adapter.closeIdleCalls.Load()
	}
	if closed != 1 {
		t.Fatalf("evicted adapter close calls = %d, want 1", closed)
	}
	if original.closeIdleCalls.Load() != 0 {
		t.Fatal("cache cleanup closed the original HTTP client")
	}
}

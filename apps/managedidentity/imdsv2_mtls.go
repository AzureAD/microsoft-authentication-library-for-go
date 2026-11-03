// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
)

// imdsV2MtlsClientCache holds this Client's configured children. Keeping it on
// Client prevents two applications with different factories from sharing a
// client solely because they received the same certificate and key identity.
type imdsV2MtlsClientCache struct {
	mu      sync.Mutex
	clients map[string]ops.HTTPClient
}

func newIMDSv2MtlsClientCache() *imdsV2MtlsClientCache {
	return &imdsV2MtlsClientCache{clients: map[string]ops.HTTPClient{}}
}

// mtlsClientCacheLimit bounds the number of certificate-scoped transports one
// Client retains. The working set is normally one entry; the cap only protects
// long-running processes across repeated certificate rotation.
const mtlsClientCacheLimit = 8

func (c *Client) mtlsClientCache() *imdsV2MtlsClientCache {
	if c.mtlsClients == nil {
		c.mtlsClients = newIMDSv2MtlsClientCache()
	}
	return c.mtlsClients
}

func (c *Client) cachedMtlsClient(key string) (ops.HTTPClient, bool) {
	cache := c.mtlsClientCache()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	client, ok := cache.clients[key]
	return client, ok
}

// publishMtlsClient publishes built unless another goroutine already published
// this key. It returns the selected client plus children the caller must close.
func (c *Client) publishMtlsClient(key string, built ops.HTTPClient) (ops.HTTPClient, []ops.HTTPClient) {
	cache := c.mtlsClientCache()
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if existing, ok := cache.clients[key]; ok {
		return existing, []ops.HTTPClient{built}
	}
	var discarded []ops.HTTPClient
	for old, client := range cache.clients {
		if len(cache.clients) < mtlsClientCacheLimit {
			break
		}
		discarded = append(discarded, client)
		delete(cache.clients, old)
	}
	cache.clients[key] = built
	return built, discarded
}

func mtlsClientCacheKey(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		return "", errors.New("managedidentity: IMDSv2 requires a binding certificate")
	}
	if cert.PrivateKey == nil {
		return "", errors.New("managedidentity: the IMDSv2 binding certificate is missing its private key")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	// The signer identity is part of the key. Restoring the same DER can
	// provision a new CNG handle after the previous handle has been closed.
	return fmt.Sprintf("%x|%p", sum, cert.PrivateKey), nil
}

// mtlsClient builds or returns the client used for the IMDSv2 token leg.
func (c *Client) mtlsClient(binding *bindingCertificate) (ops.HTTPClient, error) {
	return c.mtlsClientWithFactoryInvoker(binding, func(invoke func() error) error {
		return invoke()
	})
}

// mtlsClientForAcquisition invokes application factory/configurer code outside
// the process-wide token gate. runOutside reacquires the gate before returning,
// so token transmission remains serialized with every other managed identity
// acquisition.
func (c *Client) mtlsClientForAcquisition(
	ctx context.Context,
	binding *bindingCertificate,
	gate *miTokenGateLease,
) (ops.HTTPClient, error) {
	return c.mtlsClientWithFactoryInvoker(binding, func(invoke func() error) error {
		return gate.runOutside(ctx, invoke)
	})
}

func (c *Client) mtlsClientWithFactoryInvoker(
	binding *bindingCertificate,
	invoke func(func() error) error,
) (ops.HTTPClient, error) {
	key, err := mtlsClientCacheKey(&binding.TLS)
	if err != nil {
		return nil, err
	}
	if cached, ok := c.cachedMtlsClient(key); ok {
		return cached, nil
	}

	factory, hasFactory := c.httpClient.(MtlsHTTPClientFactory)
	if !hasFactory {
		built, err := buildIMDSv2MtlsClient(binding, c.httpClient)
		if err != nil {
			return nil, err
		}
		selected, discarded := c.publishMtlsClient(key, built)
		closeIMDSv2MtlsClients(discarded)
		return selected, nil
	}

	var selected ops.HTTPClient
	err = invoke(func() error {
		built, err := buildIMDSv2MtlsClientFromFactory(factory, binding)
		if err != nil {
			return err
		}
		var discarded []ops.HTTPClient
		selected, discarded = c.publishMtlsClient(key, built)
		closeIMDSv2MtlsClients(discarded)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return selected, nil
}

func buildIMDSv2MtlsClientFromFactory(
	factory MtlsHTTPClientFactory,
	binding *bindingCertificate,
) (ops.HTTPClient, error) {
	configurer, factoryErr := factory.NewMtlsClient()
	var resultErr error
	if isNilIMDSv2HTTPClient(configurer) {
		resultErr = errors.New("managedidentity: mTLS HTTP client factory returned a nil ClientConfigurer")
	}
	if factoryErr != nil {
		factoryErr = fmt.Errorf("managedidentity: mTLS HTTP client factory failed: %w", factoryErr)
	}
	if err := combineIMDSv2MtlsErrors(factoryErr, resultErr); err != nil {
		return nil, err
	}

	var (
		mu             sync.Mutex
		augmentCalls   int
		augmentErr     error
		augmented      *http.Client
		configurerDone bool
		lateInvocation = errors.New("managedidentity: mTLS HTTP ClientConfigurer called augment after ConfigureClient returned; augment must be called exactly once and synchronously")
	)
	augment := func(base *http.Client) (*http.Client, error) {
		mu.Lock()
		defer mu.Unlock()

		if configurerDone {
			return nil, lateInvocation
		}
		augmentCalls++
		if augmentCalls > 1 {
			err := fmt.Errorf("managedidentity: mTLS HTTP ClientConfigurer called augment %d times; ConfigureClient must call augment exactly once", augmentCalls)
			augmentErr = combineIMDSv2MtlsErrors(augmentErr, err)
			return nil, err
		}
		if base == nil {
			err := errors.New("managedidentity: mTLS HTTP ClientConfigurer called augment with a nil base *http.Client; ConfigureClient must supply a non-nil base client")
			augmentErr = combineIMDSv2MtlsErrors(augmentErr, err)
			return nil, err
		}

		var err error
		augmented, err = buildIMDSv2MtlsClient(binding, base)
		if err != nil {
			augmentErr = combineIMDSv2MtlsErrors(augmentErr, err)
		}
		return augmented, err
	}

	configurerErr := configurer.ConfigureClient(augment)

	mu.Lock()
	configurerDone = true
	calls := augmentCalls
	recordedAugmentErr := augmentErr
	built := augmented
	mu.Unlock()

	var contractErr error
	if calls != 1 {
		contractErr = fmt.Errorf("managedidentity: mTLS HTTP ClientConfigurer.ConfigureClient must call augment exactly once and synchronously, got %d calls", calls)
	}
	if configurerErr != nil {
		configurerErr = fmt.Errorf("managedidentity: mTLS HTTP ClientConfigurer.ConfigureClient failed: %w", configurerErr)
	}
	err := combineIMDSv2MtlsErrors(configurerErr, recordedAugmentErr, contractErr)
	if err == nil {
		return configurer, nil
	}

	// Before successful configuration the adapter may still forward cleanup to
	// the application's shared base client. Close only the private client MSAL
	// built, never the failed adapter.
	if built != nil {
		built.CloseIdleConnections()
	}
	return nil, err
}

// buildIMDSv2MtlsClient clones base and installs an immutable binding
// certificate snapshot without mutating caller-owned state.
func buildIMDSv2MtlsClient(binding *bindingCertificate, base ops.HTTPClient) (*http.Client, error) {
	isolated, err := copyBindingCertificate(binding)
	if err != nil {
		return nil, err
	}
	transport, err := cloneIMDSv2BaseTransport(base)
	if err != nil {
		runtime.KeepAlive(isolated)
		return nil, err
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	transport.TLSClientConfig.Certificates = nil
	transport.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return isolated, nil
	}
	if transport.TLSClientConfig.ClientSessionCache != nil {
		transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}

	client := &http.Client{}
	if configured, ok := base.(*http.Client); ok && configured != nil {
		*client = *configured
	}
	client.Transport = transport
	if client.CheckRedirect == nil {
		client.CheckRedirect = refuseIMDSv2Redirect
	}
	runtime.KeepAlive(isolated)
	return client, nil
}

func cloneIMDSv2BaseTransport(base ops.HTTPClient) (*http.Transport, error) {
	if !isNilIMDSv2HTTPClient(base) {
		client, ok := base.(*http.Client)
		if !ok {
			return nil, fmt.Errorf("managedidentity: IMDSv2 mTLS cannot use the configured HTTP client: %T is not an *http.Client and does not implement managedidentity.MtlsHTTPClientFactory, so the binding certificate cannot be installed without bypassing application middleware or routing", base)
		}
		if client.Transport != nil {
			transport, ok := client.Transport.(*http.Transport)
			if !ok {
				return nil, fmt.Errorf("managedidentity: IMDSv2 mTLS cannot use the configured HTTP client's %T Transport because the binding certificate cannot be installed on it without bypassing application middleware or routing; implement managedidentity.MtlsHTTPClientFactory on the value passed to WithHTTPClient", client.Transport)
			}
			if transport == nil {
				return nil, errors.New("managedidentity: IMDSv2 mTLS cannot use a nil *http.Transport; implement managedidentity.MtlsHTTPClientFactory on the value passed to WithHTTPClient")
			}
			if err := rejectIMDSv2TLSDialHooks(transport, "the configured HTTP client's *http.Transport"); err != nil {
				return nil, err
			}
			return transport.Clone(), nil
		}
	}
	if transport, ok := http.DefaultTransport.(*http.Transport); ok && transport != nil {
		if err := rejectIMDSv2TLSDialHooks(transport, "http.DefaultTransport"); err != nil {
			return nil, err
		}
		return transport.Clone(), nil
	}
	return nil, fmt.Errorf("managedidentity: IMDSv2 mTLS cannot use http.DefaultTransport because it is a %T, not an *http.Transport; pass an *http.Client with a usable *http.Transport or implement managedidentity.MtlsHTTPClientFactory", http.DefaultTransport)
}

func rejectIMDSv2TLSDialHooks(transport *http.Transport, source string) error {
	hook := ""
	switch {
	case transport.DialTLSContext != nil:
		hook = "DialTLSContext"
	case transport.DialTLS != nil: //nolint:staticcheck // read to reject the deprecated hook
		hook = "DialTLS"
	default:
		return nil
	}
	return fmt.Errorf("managedidentity: IMDSv2 mTLS cannot use %s because it sets %s, which bypasses TLSClientConfig and would ignore the binding certificate, TLS minimum, roots, and handshake timeout; implement managedidentity.MtlsHTTPClientFactory on the value passed to WithHTTPClient", source, hook)
}

type imdsV2MtlsErrors struct {
	errs []error
}

func (e imdsV2MtlsErrors) Error() string {
	messages := make([]string, len(e.errs))
	for i, err := range e.errs {
		messages[i] = err.Error()
	}
	return strings.Join(messages, "; ")
}

func (e imdsV2MtlsErrors) Unwrap() error {
	return e.errs[0]
}

func (e imdsV2MtlsErrors) Is(target error) bool {
	for _, err := range e.errs {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func (e imdsV2MtlsErrors) As(target interface{}) bool {
	for _, err := range e.errs {
		if errors.As(err, target) {
			return true
		}
	}
	return false
}

func combineIMDSv2MtlsErrors(errs ...error) error {
	combined := make([]error, 0, len(errs))
	for _, err := range errs {
		if err == nil {
			continue
		}
		if nested, ok := err.(imdsV2MtlsErrors); ok {
			combined = append(combined, nested.errs...)
			continue
		}
		combined = append(combined, err)
	}
	switch len(combined) {
	case 0:
		return nil
	case 1:
		return combined[0]
	default:
		return imdsV2MtlsErrors{errs: combined}
	}
}

func closeIMDSv2MtlsClients(clients []ops.HTTPClient) {
	for _, client := range clients {
		if !isNilIMDSv2HTTPClient(client) {
			client.CloseIdleConnections()
		}
	}
}

func isNilIMDSv2HTTPClient(client ops.HTTPClient) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice, reflect.UnsafePointer:
		return value.IsNil()
	default:
		return false
	}
}

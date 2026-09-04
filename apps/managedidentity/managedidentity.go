// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package managedidentity provides a client for retrieval of Managed Identity applications.
The Managed Identity Client is used to acquire a token for managed identity assigned to
an azure resource such as Azure function, app service, virtual machine, etc. to acquire a token
without using credentials.
*/
package managedidentity

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/version"
	"github.com/google/uuid"
)

// AuthResult contains the results of one token acquisition operation.
// For details see https://aka.ms/msal-net-authenticationresult
type AuthResult = base.AuthResult

type TokenSource = base.TokenSource

const (
	TokenSourceIdentityProvider = base.TokenSourceIdentityProvider
	TokenSourceCache            = base.TokenSourceCache
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS when no environment variables are set.
	DefaultToIMDS Source = "DefaultToIMDS"
	AzureArc      Source = "AzureArc"
	ServiceFabric Source = "ServiceFabric"
	CloudShell    Source = "CloudShell"
	AzureML       Source = "AzureML"
	AppService    Source = "AppService"

	// General request query parameter names
	metaHTTPHeaderName           = "Metadata"
	apiVersionQueryParameterName = "api-version"
	resourceQueryParameterName   = "resource"
	wwwAuthenticateHeaderName    = "www-authenticate"

	// UAMI query parameter name
	miQueryParameterClientId      = "client_id"
	miQueryParameterObjectId      = "object_id"
	miQueryParameterPrincipalId   = "principal_id"
	miQueryParameterMsiResourceId = "msi_res_id"
	miQueryParameterResourceId    = "mi_res_id"

	// IMDS
	imdsDefaultEndpoint           = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion                = "2018-02-01"
	systemAssignedManagedIdentity = "system_assigned_managed_identity"

	// Azure Arc
	azureArcEndpoint               = "http://127.0.0.1:40342/metadata/identity/oauth2/token"
	azureArcAPIVersion             = "2020-06-01"
	azureArcFileExtension          = ".key"
	azureArcMaxFileSizeBytes int64 = 4096
	linuxTokenPath                 = "/var/opt/azcmagent/tokens" // #nosec G101
	linuxHimdsPath                 = "/opt/azcmagent/bin/himds"
	azureConnectedMachine          = "AzureConnectedMachineAgent"
	himdsExecutableName            = "himds.exe"
	tokenName                      = "Tokens"

	// App Service
	appServiceAPIVersion = "2019-08-01"

	// AzureML
	azureMLAPIVersion = "2017-09-01"
	// Service Fabric
	serviceFabricAPIVersion = "2019-07-01-preview"

	// Environment Variables
	identityEndpointEnvVar              = "IDENTITY_ENDPOINT"
	identityHeaderEnvVar                = "IDENTITY_HEADER"
	azurePodIdentityAuthorityHostEnvVar = "AZURE_POD_IDENTITY_AUTHORITY_HOST"
	imdsEndVar                          = "IMDS_ENDPOINT"
	msiEndpointEnvVar                   = "MSI_ENDPOINT"
	msiSecretEnvVar                     = "MSI_SECRET"
	identityServerThumbprintEnvVar      = "IDENTITY_SERVER_THUMBPRINT"

	defaultRetryCount = 3
)

var retryCodesForIMDS = []int{
	http.StatusNotFound,                      // 404
	http.StatusGone,                          // 410
	http.StatusTooManyRequests,               // 429
	http.StatusInternalServerError,           // 500
	http.StatusNotImplemented,                // 501
	http.StatusBadGateway,                    // 502
	http.StatusServiceUnavailable,            // 503
	http.StatusGatewayTimeout,                // 504
	http.StatusHTTPVersionNotSupported,       // 505
	http.StatusVariantAlsoNegotiates,         // 506
	http.StatusInsufficientStorage,           // 507
	http.StatusLoopDetected,                  // 508
	http.StatusNotExtended,                   // 510
	http.StatusNetworkAuthenticationRequired, // 511
}

var retryStatusCodes = []int{
	http.StatusRequestTimeout,      // 408
	http.StatusTooManyRequests,     // 429
	http.StatusInternalServerError, // 500
	http.StatusBadGateway,          // 502
	http.StatusServiceUnavailable,  // 503
	http.StatusGatewayTimeout,      // 504
}

var getAzureArcPlatformPath = func(platform string) string {
	switch platform {
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), azureConnectedMachine, tokenName)
	case "linux":
		return linuxTokenPath
	default:
		return ""
	}
}

var getAzureArcHimdsFilePath = func(platform string) string {
	switch platform {
	case "windows":
		// The agent's binaries install under Program Files; ProgramData holds
		// only its runtime state (the token directory above). MSAL .NET probes
		// %Programfiles%\AzureConnectedMachineAgent\himds.exe
		// (ManagedIdentityClient.WindowsHimdsFilePath).
		return filepath.Join(os.Getenv("ProgramFiles"), azureConnectedMachine, himdsExecutableName)
	case "linux":
		return linuxHimdsPath
	default:
		return ""
	}
}

type Source string

type ID interface {
	value() string
}

type systemAssignedValue string // its private for a reason to make the input consistent.
type UserAssignedClientID string
type UserAssignedObjectID string
type UserAssignedResourceID string

func (s systemAssignedValue) value() string    { return string(s) }
func (c UserAssignedClientID) value() string   { return string(c) }
func (o UserAssignedObjectID) value() string   { return string(o) }
func (r UserAssignedResourceID) value() string { return string(r) }
func SystemAssigned() ID {
	return systemAssignedValue(systemAssignedManagedIdentity)
}

// cache never uses the client because instance discovery is always disabled.
var cacheManager *storage.Manager = storage.New(nil)

type Client struct {
	httpClient         ops.HTTPClient
	miType             ID
	source             Source
	serviceFabricURL   string
	authParams         authority.AuthParams
	retryPolicyEnabled bool
	canRefresh         *atomic.Value
	mtlsClientFactory  func(cert tls.Certificate) *http.Client
	// capabilities are the client capabilities set by WithClientCapabilities.
	// They are held here rather than on authParams because options run before
	// New builds authParams.
	capabilities []string
	// keyProvider overrides how the IMDSv2 binding key is produced. It is only
	// set by tests; production always uses the platform provider.
	keyProvider keyProvider
}

type AcquireTokenOptions struct {
	claims string
	// mtlsPoP requests a certificate-bound token.
	mtlsPoP bool
	// overMtls requests a bearer token acquired over a mutually authenticated
	// connection.
	overMtls bool
	// attestation requests that the binding key be attested before IMDS issues
	// a certificate for it.
	attestation bool
	// minStrength is the weakest key binding the caller will accept.
	minStrength MtlsBindingStrength
	// forceRefresh bypasses the token cache for this request.
	forceRefresh bool
}

type ClientOption func(*Client)

type AcquireTokenOption func(o *AcquireTokenOptions)

// WithClaims sets additional claims to request for the token, such as those required by token revocation or conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.claims = claims
	}
}

// WithAttestationSupport requests that the IMDSv2 binding key be attested before
// IMDS issues a certificate for it, so the issued certificate carries proof that
// the private key lives in a KeyGuard trustlet. Use it when the resource requires
// an attested credential.
//
// Attestation needs AttestationClientLib.dll, a native Windows component that is
// distributed separately and is not part of this module. Deploy it alongside the
// host executable or install it into System32. The load is restricted to the
// application directory, System32 and any directory the process itself added
// with AddDllDirectory, so a DLL dropped into the working directory or found on
// %PATH% is not picked up. It is published in the
// Microsoft.Azure.Security.KeyGuardAttestation package, under
// runtimes/win-x64/native.
//
// Without this option no attestation is attempted and the credential request goes
// out non-attested, which mirrors MSAL .NET when its optional
// Microsoft.Identity.Client.KeyAttestation package is not referenced. With it, a
// failure to attest is an error rather than a downgrade: a caller that asked for
// attestation is never silently given a credential that lacks it.
//
// Attestation is only meaningful for the IMDSv2 mTLS flow, so this option
// requires [WithMtlsProofOfPossession]; pairing it with a plain bearer-token
// request returns [ErrAttestationRequiresMtls] rather than quietly ignoring it.
func WithAttestationSupport() AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.attestation = true
	}
}

// WithMtlsPoPMinStrength requires the host to be able to bind a token at least
// as strongly as the given tier, and fails the request if it cannot.
//
// Without it, a request takes whatever binding the host offers. That is the
// right default for most callers, but it means a workload that must run on
// attested hardware has no way to say so: it would receive a token bound to a
// weaker key and never learn the difference. Setting a floor turns that into an
// error, [ErrMinStrengthNotMet], raised before any credential is issued.
//
// The check runs host capability discovery, whose result is reused for the
// lifetime of the process. Passing [MtlsBindingStrengthNone] imposes no floor
// and skips discovery entirely, which is the same as not using this option.
//
// Tokens acquired under a floor are cached separately from tokens acquired
// without one, so raising the floor cannot be satisfied by a token that was
// issued before it was set.
func WithMtlsPoPMinStrength(strength MtlsBindingStrength) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.minStrength = strength
	}
}

// WithForceRefresh skips the token cache and acquires a new token from the
// service.
//
// The cache already refreshes a token before it expires, so this is not needed
// to keep a token fresh. Use it when something outside this library has changed
// what a token should contain, for example after a role assignment, where a
// cached token is still valid but no longer carries the right authorization.
//
// It does not discard the binding certificate: the certificate identifies the
// machine and is unaffected by the token becoming stale, and re-minting one per
// call would be throttled by the metadata service.
func WithForceRefresh() AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.forceRefresh = true
	}
}

// WithHTTPClient allows for a custom HTTP client to be set. Service Fabric requires a standard
// *http.Client with a *http.Transport and does not support custom TLS dialing or verification.
func WithHTTPClient(httpClient ops.HTTPClient) ClientOption {
	return func(c *Client) {
		c.httpClient = httpClient
	}
}

// WithClientCapabilities allows configuring one or more client capabilities
// such as "CP1".
//
// Capabilities are sent to Entra with every token request, and are the way a
// caller tells Entra it can handle a claims challenge. They are only observed
// on the IMDSv2 mTLS proof-of-possession flow, which is the only managed
// identity flow in this package that talks to Entra directly; the other sources
// exchange tokens through a local endpoint that has no parameter to carry them.
// MSAL .NET applies the same restriction, listing only Service Fabric as
// additionally able to forward them
// (ManagedIdentitySourceExtensions.s_supportsClaimsAndCaps).
//
// This is a client option rather than a per-request one because a capability is
// a statement about the calling application, which does not vary by request.
// MSAL .NET places it on the application builder for the same reason
// (ManagedIdentityApplicationBuilder.WithClientCapabilities).
func WithClientCapabilities(capabilities []string) ClientOption {
	return func(c *Client) {
		// The slice is not copied here: New passes it to
		// authority.NewClientCapabilities, which builds its own
		// representations and does not retain it.
		c.capabilities = capabilities
	}
}

func WithRetryPolicyDisabled() ClientOption {
	return func(c *Client) {
		c.retryPolicyEnabled = false
	}
}

// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned], [UserAssignedClientID], [UserAssignedResourceID], [UserAssignedObjectID]
//
// Options: [WithHTTPClient]
func New(id ID, options ...ClientOption) (Client, error) {
	source, err := GetSource()
	if err != nil {
		return Client{}, err
	}

	// Check for user-assigned restrictions based on the source
	switch source {
	case AzureML:
		switch id.(type) {
		case UserAssignedObjectID, UserAssignedResourceID:
			return Client{}, errors.New("Azure ML supports specifying a user-assigned managed identity by client ID only")
		}
	case CloudShell:
		switch id.(type) {
		case UserAssignedClientID, UserAssignedResourceID, UserAssignedObjectID:
			return Client{}, errors.New("Cloud Shell doesn't support user-assigned managed identities")
		}
	case ServiceFabric:
		switch id.(type) {
		case UserAssignedClientID, UserAssignedResourceID, UserAssignedObjectID:
			return Client{}, errors.New("Service Fabric API doesn't support specifying a user-assigned identity. The identity is determined by cluster resource configuration. See https://aka.ms/servicefabricmi")
		}
	}

	switch t := id.(type) {
	case UserAssignedClientID:
		if len(string(t)) == 0 {
			return Client{}, fmt.Errorf("empty %T", t)
		}
	case UserAssignedResourceID:
		if len(string(t)) == 0 {
			return Client{}, fmt.Errorf("empty %T", t)
		}
	case UserAssignedObjectID:
		if len(string(t)) == 0 {
			return Client{}, fmt.Errorf("empty %T", t)
		}
	case systemAssignedValue:
	default:
		return Client{}, fmt.Errorf("unsupported type %T", id)
	}
	zero := atomic.Value{}
	zero.Store(false)
	client := Client{
		miType:             id,
		httpClient:         shared.DefaultClient,
		retryPolicyEnabled: true,
		source:             source,
		canRefresh:         &zero,
	}
	for _, option := range options {
		option(&client)
	}
	if source == ServiceFabric {
		serviceFabricClient, serviceFabricURL, err := serviceFabricCertificateVerifiedHTTPClient(client.httpClient)
		if err != nil {
			return Client{}, err
		}
		client.httpClient = serviceFabricClient
		client.serviceFabricURL = serviceFabricURL
	}
	fakeAuthInfo, err := authority.NewInfoFromAuthorityURI("https://login.microsoftonline.com/managed_identity", false, true)
	if err != nil {
		return Client{}, err
	}
	client.authParams = authority.NewAuthParams(client.miType.value(), fakeAuthInfo)
	if len(client.capabilities) > 0 {
		cc, err := authority.NewClientCapabilities(client.capabilities)
		if err != nil {
			return Client{}, err
		}
		client.authParams.Capabilities = cc
	}
	return client, nil
}

// GetSource detects and returns the managed identity source available on the environment.
func GetSource() (Source, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	identityHeader := os.Getenv(identityHeaderEnvVar)
	identityServerThumbprint := os.Getenv(identityServerThumbprintEnvVar)
	msiEndpoint := os.Getenv(msiEndpointEnvVar)
	msiSecret := os.Getenv(msiSecretEnvVar)
	imdsEndpoint := os.Getenv(imdsEndVar)

	if identityEndpoint != "" && identityHeader != "" {
		if identityServerThumbprint != "" {
			return ServiceFabric, nil
		}
		return AppService, nil
	} else if msiEndpoint != "" {
		if msiSecret != "" {
			return AzureML, nil
		} else {
			return CloudShell, nil
		}
	} else if isAzureArcEnvironment(identityEndpoint, imdsEndpoint) {
		return AzureArc, nil
	}

	return DefaultToIMDS, nil
}

// This function wraps time.Now() and is used for refreshing the application
// was created to test the function against refreshin
var now = time.Now

// miTokenGate serializes every managed identity token acquisition in the
// process.
//
// The managed identity endpoints are per-machine services with their own
// throttling, and a service that takes a token per inbound request will fan out
// concurrent acquisitions for the same identity and resource on a cold cache.
// Left unserialized those become simultaneous requests to a single local
// endpoint, which answers 429; serialized, the first one populates the cache and
// the rest read it. MSAL .NET holds the same process-wide gate for the same
// reason (ManagedIdentityAuthRequest.s_semaphoreSlim: "Requests to a managed
// identity endpoint must be throttled; otherwise, the endpoint will throw a HTTP
// 429.").
//
// It is a buffered channel rather than a mutex so the wait can be abandoned when
// the caller's context is cancelled. Ordering among waiters is not guaranteed
// and does not need to be.
var miTokenGate = make(chan struct{}, 1)

// acquireMITokenGate blocks until this goroutine holds the gate, and returns the
// function that releases it.
func acquireMITokenGate(ctx context.Context) (func(), error) {
	select {
	case miTokenGate <- struct{}{}:
		return func() { <-miTokenGate }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (c Client) AcquireToken(ctx context.Context, resource string, options ...AcquireTokenOption) (AuthResult, error) {
	resource = strings.TrimSuffix(resource, "/.default")
	o := AcquireTokenOptions{}
	for _, option := range options {
		option(&o)
	}
	if err := o.validate(c.source); err != nil {
		return AuthResult{}, err
	}
	c.authParams.Scopes = []string{resource}
	o.stampCacheComponents(&c.authParams)

	// Claims and an explicit force-refresh both mean the caller has said the
	// cached token is not acceptable, so the cache is skipped in both
	// directions: not read here, and not re-read under the gate below. MSAL
	// .NET draws the same line (ManagedIdentityAuthRequest.GetAccessTokenAsync).
	useCache := o.claims == "" && !o.forceRefresh

	if useCache {
		ar, refreshDue, hit, err := c.cachedAuthResult(ctx, o)
		if err != nil {
			return AuthResult{}, err
		}
		if hit {
			// A token inside its refresh window is still usable, so this
			// refresh runs on behalf of a caller that already has an answer.
			// It goes straight to the network: re-reading the cache under the
			// gate would find the very token that asked to be refreshed and
			// return it unchanged. .NET makes the same exception for
			// CacheRefreshReason.ProactivelyRefreshed.
			if refreshDue && c.canRefresh.CompareAndSwap(false, true) {
				defer c.canRefresh.Store(false)
				if tr, er := c.serializedToken(ctx, resource, o, false); er == nil {
					return tr, nil
				}
			}
			return ar, nil
		}
	}
	return c.serializedToken(ctx, resource, o, useCache)
}

// serializedToken acquires a token while holding the process-wide managed
// identity gate.
//
// recheckCache asks for one more cache read after the gate is held. A caller
// that queued behind a cold-start stampede was told the cache was empty before
// it began waiting, and by the time it is admitted the holder has usually
// filled it; without the re-read every waiter would go on to make the request
// the gate exists to prevent. .NET re-reads at the same point and for the same
// stated reason ("in case the previous request cached a new token").
func (c Client) serializedToken(ctx context.Context, resource string, o AcquireTokenOptions, recheckCache bool) (AuthResult, error) {
	release, err := acquireMITokenGate(ctx)
	if err != nil {
		return AuthResult{}, err
	}
	defer release()

	if recheckCache {
		if ar, _, hit, err := c.cachedAuthResult(ctx, o); err == nil && hit {
			return ar, nil
		}
	}
	return c.getToken(ctx, resource, o)
}

// cachedAuthResult reports the token this request would be served from the
// cache, if any.
//
// It resolves the binding certificate first because a certificate-bound token
// is cached under a scheme keyed by that certificate, so the cache cannot be
// consulted until it is known. When none has been issued yet no bound token can
// have been cached either, and reading with the default scheme would match a
// bearer token and hand back an unbound credential to a request that explicitly
// asked for a bound one.
//
// refreshDue reports that a hit is inside its proactive-refresh window. c is
// taken by value so the resolved scheme does not escape to the caller.
func (c Client) cachedAuthResult(ctx context.Context, o AcquireTokenOptions) (_ AuthResult, refreshDue bool, hit bool, _ error) {
	var cachedBinding *bindingCertificate
	if o.mtlsPoP {
		binding, ok := certCache.get(cacheKey(c.miType, o.attestation))
		if !ok {
			return AuthResult{}, false, false, nil
		}
		// Serving a bound token straight from the cache skips leg 1, so the
		// validation a normal acquisition performs has to happen here too. A
		// certificate whose key was lost to a container reset still parses and
		// still has the same thumbprint, so without this the caller would get a
		// cached token plus a certificate it can no longer prove possession of.
		if needsRefresh(binding) || isOrphaned(binding, c.bindingKeyProvider()) {
			_ = binding.Close()
			return AuthResult{}, false, false, nil
		}
		cachedBinding = binding
		defer func() { _ = binding.Close() }()
		c.authParams.AuthnScheme = authority.NewMtlsPoPAuthenticationScheme(binding.Leaf)
	}

	stResp, err := cacheManager.Read(ctx, c.authParams)
	if err != nil {
		return AuthResult{}, false, false, err
	}
	ar, err := base.AuthResultFromStorage(stResp)
	if err != nil {
		return AuthResult{}, false, false, nil
	}
	refreshDue = !stResp.AccessToken.RefreshOn.T.IsZero() && !stResp.AccessToken.RefreshOn.T.After(now())
	ar.AccessToken, err = c.authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
	if err != nil {
		return AuthResult{}, false, false, err
	}
	// A bound token is only usable by a caller that can also present the
	// certificate it is bound to, so serving one from the cache without the
	// certificate hands back a token that every resource rejects. The scheme
	// lookup above already resolved that certificate.
	if o.mtlsPoP {
		ar.BindingCertificate = copyBindingCertificate(cachedBinding)
	}
	return ar, refreshDue, true, nil
}

func (c Client) getToken(ctx context.Context, resource string, o AcquireTokenOptions) (AuthResult, error) {
	// The IMDSv2 certificate path replaces the ordinary IMDS request entirely.
	// There is deliberately no fallback to IMDSv1 here: quietly returning an
	// unbound token would defeat the protection the caller asked for.
	if o.usesIMDSv2() {
		return c.acquireTokenForIMDSv2(ctx, resource, o)
	}
	switch c.source {
	case AzureArc:
		return c.acquireTokenForAzureArc(ctx, resource)
	case AzureML:
		return c.acquireTokenForAzureML(ctx, resource)
	case CloudShell:
		return c.acquireTokenForCloudShell(ctx, resource)
	case DefaultToIMDS:
		return c.acquireTokenForIMDS(ctx, resource)
	case AppService:
		return c.acquireTokenForAppService(ctx, resource)
	case ServiceFabric:
		return c.acquireTokenForServiceFabric(ctx, resource)
	default:
		return AuthResult{}, fmt.Errorf("unsupported source %q", c.source)
	}
}

func (c Client) acquireTokenForAppService(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createAppServiceAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForIMDS(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createIMDSAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForCloudShell(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createCloudShellAuthRequest(ctx, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForAzureML(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createAzureMLAuthRequest(ctx, c.miType, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForServiceFabric(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createServiceFabricAuthRequest(ctx, c.serviceFabricURL, resource)
	if err != nil {
		return AuthResult{}, err
	}
	tokenResponse, err := c.getTokenForRequest(req, resource)
	if err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

func (c Client) acquireTokenForAzureArc(ctx context.Context, resource string) (AuthResult, error) {
	req, err := createAzureArcAuthRequest(ctx, c.miType, resource, "")
	if err != nil {
		return AuthResult{}, err
	}

	response, err := c.httpClient.Do(req)
	if err != nil {
		return AuthResult{}, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		return AuthResult{}, fmt.Errorf("expected a 401 response, received %d", response.StatusCode)
	}

	secret, err := c.getAzureArcSecretKey(response, runtime.GOOS)
	if err != nil {
		return AuthResult{}, err
	}

	secondRequest, err := createAzureArcAuthRequest(ctx, c.miType, resource, string(secret))
	if err != nil {
		return AuthResult{}, err
	}

	tokenResponse, err := c.getTokenForRequest(secondRequest, resource)
	if err != nil {
		return AuthResult{}, err
	}
	if err := verifyAzureArcUserAssignedIdentity(c.miType, tokenResponse); err != nil {
		return AuthResult{}, err
	}
	return authResultFromToken(c.authParams, tokenResponse)
}

// setUserAssignedQueryParam adds the user-assigned identity selector to params. Azure Arc and IMDS
// both use the IMDS "msi_res_id" spelling for the resource id; a system-assigned identity adds
// nothing. An unsupported ID type is rejected (New already validates the caller's input).
func setUserAssignedQueryParam(params url.Values, id ID) error {
	switch t := id.(type) {
	case UserAssignedClientID:
		params.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		params.Set(miQueryParameterMsiResourceId, string(t))
	case UserAssignedObjectID:
		params.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue:
	default:
		return fmt.Errorf("unsupported type %T", id)
	}
	return nil
}

// verifyAzureArcUserAssignedIdentity fails closed when a user-assigned identity was requested
// but Azure Arc did not confirm it in the token response. A legacy Azure Arc agent ignores the
// client_id / msi_res_id / object_id selector and silently returns the machine's system-assigned
// identity. An agent that supports user-assigned managed identity echoes the identity it used in
// the token response; when that echo is missing or does not match the requested selector, MSAL
// must not hand back a token for a different identity than the one requested.
func verifyAzureArcUserAssignedIdentity(id ID, token accesstokens.TokenResponse) error {
	// Reuse the request selector mapping so the request and validation stay in lock-step.
	selector := url.Values{}
	if err := setUserAssignedQueryParam(selector, id); err != nil {
		return err
	}
	if len(selector) == 0 {
		// System-assigned: there is no requested identity to confirm.
		return nil
	}
	var name, requested string
	for k := range selector {
		name, requested = k, selector.Get(k)
	}
	// Accept either resource-id spelling on the echo as a safety net; Azure Arc returns msi_res_id.
	keys := []string{name}
	if name == miQueryParameterMsiResourceId {
		keys = append(keys, miQueryParameterResourceId)
	}
	echoed := additionalStringField(token.AdditionalFields, keys...)
	// Compare case-insensitively: client_id / object_id are GUIDs, and an ARM resource id can
	// legitimately differ in segment casing.
	if echoed == "" || !strings.EqualFold(echoed, requested) {
		return errors.New("azure arc did not confirm the requested user-assigned managed identity in the token response; the agent likely does not support user-assigned managed identities and returned the system-assigned identity")
	}
	return nil
}

// additionalStringField returns the first non-empty string value among the given keys from a
// token response's additional (untyped) fields.
func additionalStringField(fields map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := fields[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func authResultFromToken(authParams authority.AuthParams, token accesstokens.TokenResponse) (AuthResult, error) {
	if cacheManager == nil {
		return AuthResult{}, errors.New("cache instance is nil")
	}
	account, err := cacheManager.Write(authParams, token)
	if err != nil {
		return AuthResult{}, err
	}
	// if refreshOn is not set, set it to half of the time until expiry if expiry is more than 2 hours away
	if token.RefreshOn.T.IsZero() {
		if lifetime := time.Until(token.ExpiresOn); lifetime > 2*time.Hour {
			token.RefreshOn.T = time.Now().Add(lifetime / 2)
		}
	}
	ar, err := base.NewAuthResult(token, account)
	if err != nil {
		return AuthResult{}, err
	}
	ar.AccessToken, err = authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
	return ar, err
}

// contains checks if the element is present in the list.
func contains[T comparable](list []T, element T) bool {
	for _, v := range list {
		if v == element {
			return true
		}
	}
	return false
}

// bufferResponseBody reads resp.Body fully into memory and replaces it with an
// in-memory reader. This lets the caller consume the response after the
// per-attempt context that produced it has been canceled. See issue #634.
func bufferResponseBody(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// retry performs an HTTP request with retries based on the provided options.
func (c Client) retry(maxRetries int, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	// cancelPrev cancels the context of the previous attempt. It is invoked only
	// after that attempt's body has been drained, so the transport connection can
	// still be reused, while avoiding the resource retention of deferring every
	// per-attempt cancel until retry() returns.
	var cancelPrev context.CancelFunc
	retrylist := retryStatusCodes
	if c.source == DefaultToIMDS {
		retrylist = retryCodesForIMDS
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		tryCtx, tryCancel := context.WithTimeout(req.Context(), time.Minute)
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		if cancelPrev != nil {
			cancelPrev()
		}
		cancelPrev = tryCancel
		cloneReq := req.Clone(tryCtx)
		resp, err = c.httpClient.Do(cloneReq)
		succeeded := err == nil && !contains(retrylist, resp.StatusCode)
		if succeeded || attempt == maxRetries-1 {
			// Buffer the body into memory while tryCtx is still alive so the
			// caller can read resp.Body after we cancel this attempt's context.
			// Without this, the deferred/explicit cancel would race the caller's
			// read and surface as "context canceled" on an otherwise successful
			// response. See issue #634.
			if bufErr := bufferResponseBody(resp); bufErr != nil && err == nil {
				err = bufErr
			}
			tryCancel()
			return resp, err
		}
		select {
		case <-time.After(time.Second):
		case <-req.Context().Done():
			err = req.Context().Err()
			tryCancel()
			return resp, err
		}
	}
	if cancelPrev != nil {
		cancelPrev()
	}
	return resp, err
}

func (c Client) getTokenForRequest(req *http.Request, resource string) (accesstokens.TokenResponse, error) {
	r := accesstokens.TokenResponse{}
	var resp *http.Response
	var err error

	if c.retryPolicyEnabled {
		resp, err = c.retry(defaultRetryCount, req)
	} else {
		resp, err = c.httpClient.Do(req)
	}
	if err != nil {
		return r, err
	}
	responseBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return r, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
	default:
		sd := strings.TrimSpace(string(responseBytes))
		if sd != "" {
			return r, errors.CallErr{
				Req:  req,
				Resp: resp,
				Err: fmt.Errorf("http call(%s)(%s) error: reply status code was %d:\n%s",
					req.URL.String(),
					req.Method,
					resp.StatusCode,
					sd),
			}
		}
		return r, errors.CallErr{
			Req:  req,
			Resp: resp,
			Err:  fmt.Errorf("http call(%s)(%s) error: reply status code was %d", req.URL.String(), req.Method, resp.StatusCode),
		}
	}

	err = json.Unmarshal(responseBytes, &r)
	if err != nil {
		return r, errors.InvalidJsonErr{
			Err: fmt.Errorf("error parsing the json error: %s", err),
		}
	}
	// Capture the raw response fields so source-specific logic (such as the Azure Arc
	// user-assigned identity echo check) can read fields the typed response drops.
	var additionalFields map[string]interface{}
	if json.Unmarshal(responseBytes, &additionalFields) == nil {
		r.AdditionalFields = additionalFields
	}
	r.GrantedScopes.Slice = append(r.GrantedScopes.Slice, resource)

	return r, err
}

func createAppServiceAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-IDENTITY-HEADER", os.Getenv(identityHeaderEnvVar))
	q := req.URL.Query()
	q.Set("api-version", appServiceAPIVersion)
	q.Set("resource", resource)
	switch t := id.(type) {
	case UserAssignedClientID:
		q.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		q.Set(miQueryParameterResourceId, string(t))
	case UserAssignedObjectID:
		q.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue:
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}
	req.URL.RawQuery = q.Encode()
	return req, nil
}

func createIMDSAuthRequest(ctx context.Context, id ID, resource string) (*http.Request, error) {
	msiEndpoint, err := url.Parse(imdsDefaultEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsDefaultEndpoint, err)
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, imdsAPIVersion)
	msiParameters.Set(resourceQueryParameterName, resource)

	if err := setUserAssignedQueryParam(msiParameters, id); err != nil {
		return nil, err
	}

	msiEndpoint.RawQuery = msiParameters.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}
	req.Header.Set(metaHTTPHeaderName, "true")
	req.Header.Set("x-client-SKU", version.SKU)
	req.Header.Set("x-client-Ver", version.Version)
	req.Header.Set("x-ms-client-request-id", uuid.New().String())
	return req, nil
}

func createAzureArcAuthRequest(ctx context.Context, id ID, resource string, key string) (*http.Request, error) {
	identityEndpoint := os.Getenv(identityEndpointEnvVar)
	if identityEndpoint == "" {
		identityEndpoint = azureArcEndpoint
	}
	msiEndpoint, parseErr := url.Parse(identityEndpoint)

	if parseErr != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", identityEndpoint, parseErr)
	}

	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQueryParameterName, azureArcAPIVersion)
	msiParameters.Set(resourceQueryParameterName, resource)

	// Azure Arc honors the IMDS msi_res_id spelling for the resource-id selector; the mi_res_id
	// spelling is silently ignored and returns the system-assigned identity.
	if err := setUserAssignedQueryParam(msiParameters, id); err != nil {
		return nil, err
	}

	msiEndpoint.RawQuery = msiParameters.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}
	req.Header.Set(metaHTTPHeaderName, "true")

	if key != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", key))
	}

	return req, nil
}

func isAzureArcEnvironment(identityEndpoint, imdsEndpoint string) bool {
	if identityEndpoint != "" && imdsEndpoint != "" {
		return true
	}
	himdsFilePath := getAzureArcHimdsFilePath(runtime.GOOS)
	if himdsFilePath != "" {
		if _, err := os.Stat(himdsFilePath); err == nil {
			return true
		}
	}
	return false
}

func (c *Client) getAzureArcSecretKey(response *http.Response, platform string) (string, error) {
	wwwAuthenticateHeader := response.Header.Get(wwwAuthenticateHeaderName)

	if len(wwwAuthenticateHeader) == 0 {
		return "", errors.New("response has no www-authenticate header")
	}

	// check if the platform is supported
	expectedSecretFilePath := getAzureArcPlatformPath(platform)
	if expectedSecretFilePath == "" {
		return "", errors.New("platform not supported, expected linux or windows")
	}

	parts := strings.Split(wwwAuthenticateHeader, "Basic realm=")
	if len(parts) < 2 {
		return "", fmt.Errorf("basic realm= not found in the string, instead found: %s", wwwAuthenticateHeader)
	}

	secretFilePath := parts

	// check that the file in the file path is a .key file
	fileName := filepath.Base(secretFilePath[1])
	if !strings.HasSuffix(fileName, azureArcFileExtension) {
		return "", fmt.Errorf("invalid file extension, expected %s, got %s", azureArcFileExtension, filepath.Ext(fileName))
	}

	// check that file path from header matches the expected file path for the platform
	if expectedSecretFilePath != filepath.Dir(secretFilePath[1]) {
		return "", fmt.Errorf("invalid file path, expected %s, got %s", expectedSecretFilePath, filepath.Dir(secretFilePath[1]))
	}

	fileInfo, err := os.Stat(secretFilePath[1])
	if err != nil {
		return "", fmt.Errorf("failed to get metadata for %s due to error: %s", secretFilePath[1], err)
	}

	// Throw an error if the secret file's size is greater than 4096 bytes
	if s := fileInfo.Size(); s > azureArcMaxFileSizeBytes {
		return "", fmt.Errorf("invalid secret file size, expected %d, file size was %d", azureArcMaxFileSizeBytes, s)
	}

	// Attempt to read the contents of the secret file
	secret, err := os.ReadFile(secretFilePath[1])
	if err != nil {
		return "", fmt.Errorf("failed to read %q due to error: %s", secretFilePath[1], err)
	}

	return string(secret), nil
}

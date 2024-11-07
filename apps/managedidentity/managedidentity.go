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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/storage"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

const (
	// DefaultToIMDS indicates that the source is defaulted to IMDS when no environment variables are set.
	DefaultToIMDS Source = "DefaultToIMDS"
	AzureArc      Source = "AzureArc"
	ServiceFabric Source = "ServiceFabric"
	CloudShell    Source = "CloudShell"
	AppService    Source = "AppService"

	// General request querry parameter names
	metaHTTPHeaderName            = "Metadata"
	apiVersionQuerryParameterName = "api-version"
	resourceQuerryParameterName   = "resource"

	// UAMI querry parameter name
	miQueryParameterClientId   = "client_id"
	miQueryParameterObjectId   = "object_id"
	miQueryParameterResourceId = "msi_res_id"

	// IMDS
	imdsEndpoint   = "http://169.254.169.254/metadata/identity/oauth2/token"
	imdsAPIVersion = "2018-02-01"

	systemAssignedManagedIdentity = "system_assigned_managed_identity"
	defaultRetryCount             = 3
)

// retry on these codes
var retryStatusCodes = []int{
	http.StatusRequestTimeout,      // 408
	http.StatusTooManyRequests,     // 429
	http.StatusInternalServerError, // 500
	http.StatusBadGateway,          // 502
	http.StatusServiceUnavailable,  // 503
	http.StatusGatewayTimeout,      // 504
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
	retryPolicyEnabled bool
}

type ClientOptions struct {
	httpClient         ops.HTTPClient
	retryPolicyEnabled bool
}

type AcquireTokenOptions struct {
	claims string
}

type ClientOption func(o *ClientOptions)

type AcquireTokenOption func(o *AcquireTokenOptions)

// WithClaims sets additional claims to request for the token, such as those required by token revocation or conditional access policies.
// Use this option when Azure AD returned a claims challenge for a prior request. The argument must be decoded.
func WithClaims(claims string) AcquireTokenOption {
	return func(o *AcquireTokenOptions) {
		o.claims = claims
	}
}

// WithHTTPClient allows for a custom HTTP client to be set.
func WithHTTPClient(httpClient ops.HTTPClient) ClientOption {
	return func(o *ClientOptions) {
		o.httpClient = httpClient
	}
}

func WithRetryPolicyDisabled() ClientOption {
	return func(o *ClientOptions) {
		o.retryPolicyEnabled = false
	}
}

// Client to be used to acquire tokens for managed identity.
// ID: [SystemAssigned], [UserAssignedClientID], [UserAssignedResourceID], [UserAssignedObjectID]
//
// Options: [WithHTTPClient]
func New(id ID, options ...ClientOption) (Client, error) {
	opts := ClientOptions{
		httpClient:         shared.DefaultClient,
		retryPolicyEnabled: true,
	}
	for _, option := range options {
		option(&opts)
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
	client := Client{
		miType:             id,
		httpClient:         opts.httpClient,
		retryPolicyEnabled: opts.retryPolicyEnabled,
	}
	return client, nil
}

func createIMDSAuthRequest(ctx context.Context, id ID, resource string, claims string) (*http.Request, error) {
	var msiEndpoint *url.URL
	msiEndpoint, err := url.Parse(imdsEndpoint)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse %q: %s", imdsEndpoint, err)
	}
	msiParameters := msiEndpoint.Query()
	msiParameters.Set(apiVersionQuerryParameterName, imdsAPIVersion)
	resource = strings.TrimSuffix(resource, "/.default")
	msiParameters.Set(resourceQuerryParameterName, resource)

	if len(claims) > 0 {
		msiParameters.Set("claims", claims)
	}

	switch t := id.(type) {
	case UserAssignedClientID:
		msiParameters.Set(miQueryParameterClientId, string(t))
	case UserAssignedResourceID:
		msiParameters.Set(miQueryParameterResourceId, string(t))
	case UserAssignedObjectID:
		msiParameters.Set(miQueryParameterObjectId, string(t))
	case systemAssignedValue: // not adding anything
	default:
		return nil, fmt.Errorf("unsupported type %T", id)
	}

	msiEndpoint.RawQuery = msiParameters.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, msiEndpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request %s", err)
	}
	req.Header.Set(metaHTTPHeaderName, "true")
	return req, nil
}

// Contains checks if the element is present in the list.
func contains[T comparable](list []T, element T) bool {
	for _, v := range list {
		if v == element {
			return true
		}
	}
	return false
}

// retry performs an HTTP request with retries based on the provided options.
func retry(maxRetries int, c ops.HTTPClient, req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		tryCtx, tryCancel := context.WithTimeout(req.Context(), time.Second*15)
		defer tryCancel()
		cloneReq := req.Clone(tryCtx)
		resp, err = c.Do(cloneReq)
		if err == nil && !contains(retryStatusCodes, resp.StatusCode) {
			return resp, nil
		}
		if attempt == maxRetries-1 {
			return resp, err
		}
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		select {
		case <-time.After(time.Second):
		case <-req.Context().Done():
			err = req.Context().Err()
			return resp, err
		}
	}
	return resp, err
}

func (client Client) getTokenForRequest(req *http.Request) (accesstokens.TokenResponse, error) {
	retryCount := 3
	if !client.retryPolicyEnabled {
		retryCount = 1
	}
	resp, err := retry(retryCount, client.httpClient, req)
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	responseBytes, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return accesstokens.TokenResponse{}, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted:
	default:
		sd := strings.TrimSpace(string(responseBytes))
		if sd != "" {
			return accesstokens.TokenResponse{}, errors.CallErr{
				Req:  req,
				Resp: resp,
				Err: fmt.Errorf("http call(%s)(%s) error: reply status code was %d:\n%s",
					req.URL.String(),
					req.Method,
					resp.StatusCode,
					sd),
			}
		}
		return accesstokens.TokenResponse{}, errors.CallErr{
			Req:  req,
			Resp: resp,
			Err:  fmt.Errorf("http call(%s)(%s) error: reply status code was %d", req.URL.String(), req.Method, resp.StatusCode),
		}
	}
	var r accesstokens.TokenResponse
	err = json.Unmarshal(responseBytes, &r)
	r.GrantedScopes.Slice = append(r.GrantedScopes.Slice, req.URL.Query().Get(resourceQuerryParameterName))
	return r, err
}

// Acquires tokens from the configured managed identity on an azure resource.
//
// Resource: scopes application is requesting access to
// Options: [WithClaims]
func (client Client) AcquireToken(ctx context.Context, resource string, options ...AcquireTokenOption) (base.AuthResult, error) {
	o := AcquireTokenOptions{}
	for _, option := range options {
		option(&o)
	}
	req, err := createIMDSAuthRequest(ctx, client.miType, resource, o.claims)
	if err != nil {
		return base.AuthResult{}, err
	}

	fakeAuthInfo, err := authority.NewInfoFromAuthorityURI("https://login.microsoftonline.com/managed_identity", false, true)
	if err != nil {
		return base.AuthResult{}, err
	}
	fakeAuthParams := authority.NewAuthParams(client.miType.value(), fakeAuthInfo)
	// ignore cached access tokens when given claims
	if o.claims == "" {
		if cacheManager == nil {
			return base.AuthResult{}, errors.New("cache instance is nil")
		}
		storageTokenResponse, err := cacheManager.Read(ctx, fakeAuthParams)
		if err != nil {
			return base.AuthResult{}, err
		}
		ar, err := base.AuthResultFromStorage(storageTokenResponse)
		if err == nil {
			ar.AccessToken, err = fakeAuthParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
			return ar, err
		}
	}
	tokenResponse, err := client.getTokenForRequest(req)
	if err != nil {
		return base.AuthResult{}, err
	}
	return authResultFromToken(fakeAuthParams, tokenResponse)
}

func authResultFromToken(authParams authority.AuthParams, token accesstokens.TokenResponse) (base.AuthResult, error) {
	if cacheManager == nil {
		return base.AuthResult{}, fmt.Errorf("cache instance is nil")
	}
	account, err := cacheManager.Write(authParams, token)
	if err != nil {
		return base.AuthResult{}, err
	}
	ar, err := base.NewAuthResult(token, account)
	if err != nil {
		return base.AuthResult{}, err
	}
	ar.AccessToken, err = authParams.AuthnScheme.FormatAccessToken(ar.AccessToken)
	return ar, err
}

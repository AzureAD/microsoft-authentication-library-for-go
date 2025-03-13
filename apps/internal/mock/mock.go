// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package mock

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

type response struct {
	body     []byte
	callback func(*http.Request)
	code     int
	headers  http.Header
}

type responseOption interface {
	apply(*response)
}

type respOpt func(*response)

func (fn respOpt) apply(r *response) {
	fn(r)
}

// WithBody sets the HTTP response's body to the specified value.
func WithBody(b []byte) responseOption {
	return respOpt(func(r *response) {
		r.body = b
	})
}

// WithCallback sets a callback to invoke before returning the response.
func WithCallback(callback func(*http.Request)) responseOption {
	return respOpt(func(r *response) {
		r.callback = callback
	})
}

// WithHTTPHeader sets the HTTP headers of the response to the specified value.
func WithHTTPHeader(header http.Header) responseOption {
	return respOpt(func(r *response) {
		r.headers = header
	})
}

// WithHTTPStatusCode sets the HTTP statusCode of response to the specified value.
func WithHTTPStatusCode(statusCode int) responseOption {
	return respOpt(func(r *response) {
		r.code = statusCode
	})
}

// Client is a mock HTTP client that returns a sequence of responses. Use AppendResponse to specify the sequence.
type Client struct {
	mu   *sync.Mutex
	resp []response
}

func NewClient() *Client {
	return &Client{mu: &sync.Mutex{}}
}

func (c *Client) AppendResponse(opts ...responseOption) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := response{code: http.StatusOK, headers: http.Header{}}
	for _, o := range opts {
		o.apply(&r)
	}
	c.resp = append(c.resp, r)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
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
func (*Client) CloseIdleConnections() {}

func GetAccessTokenBody(accessToken, idToken, refreshToken, clientInfo string, expiresIn, refreshIn int) []byte {
	// Start building the body with the common fields
	body := fmt.Sprintf(
		`{"access_token": "%s","expires_in": %d,"expires_on": %d,"token_type": "Bearer"`,
		accessToken, expiresIn, time.Now().Add(time.Duration(expiresIn)*time.Second).Unix(),
	)

	// Conditionally add the "refresh_in" field if refreshIn is provided
	if refreshIn > 0 {
		body += fmt.Sprintf(`, "refresh_in":"%d"`, refreshIn)
	}

	// Add the optional fields if they are provided
	if clientInfo != "" {
		body += fmt.Sprintf(`, "client_info": "%s"`, clientInfo)
	}
	if idToken != "" {
		body += fmt.Sprintf(`, "id_token": "%s"`, idToken)
	}
	if refreshToken != "" {
		body += fmt.Sprintf(`, "refresh_token": "%s"`, refreshToken)
	}

	// Close the JSON string
	body += "}"

	return []byte(body)
}

func GetIDToken(tenant, issuer string) string {
	now := time.Now().Unix()
	payload := []byte(fmt.Sprintf(`{"aud": "%s","exp": %d,"iat": %d,"iss": "%s","tid": "%s"}`, tenant, now+3600, now, issuer, tenant))
	return fmt.Sprintf("header.%s.signature", base64.RawStdEncoding.EncodeToString(payload))
}

func GetInstanceDiscoveryBody(host, tenant string) []byte {
	authority := fmt.Sprintf("https://%s/%s", host, tenant)
	body := fmt.Sprintf(`{"tenant_discovery_endpoint": "%s/v2.0/.well-known/openid-configuration","api-version": "1.1","metadata": [{"preferred_network": "%s","preferred_cache": "%s","aliases": ["%s"]}]}`,
		authority, host, host, host,
	)
	headers := http.Header{}
	headers.Add("Content-Type", "application/json; charset=utf-8")
	return []byte(body)
}

func GetTenantDiscoveryBody(host, tenant string) []byte {
	authority := fmt.Sprintf("https://%s/%s", host, tenant)
	content := strings.ReplaceAll(`{"token_endpoint": "{authority}/oauth2/v2.0/token",
		"token_endpoint_auth_methods_supported": [
			"client_secret_post",
			"private_key_jwt",
			"client_secret_basic"
		],
		"jwks_uri": "{authority}/discovery/v2.0/keys",
		"response_modes_supported": [
			"query",
			"fragment",
			"form_post"
		],
		"subject_types_supported": [
			"pairwise"
		],
		"id_token_signing_alg_values_supported": [
			"RS256"
		],
		"response_types_supported": [
			"code",
			"id_token",
			"code id_token",
			"id_token token"
		],
		"scopes_supported": [
			"openid",
			"profile",
			"email",
			"offline_access"
		],
		"issuer": "{authority}/v2.0",
		"request_uri_parameter_supported": false,
		"userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
		"authorization_endpoint": "{authority}/oauth2/v2.0/authorize",
		"device_authorization_endpoint": "{authority}/oauth2/v2.0/devicecode",
		"http_logout_supported": true,
		"frontchannel_logout_supported": true,
		"end_session_endpoint": "{authority}/oauth2/v2.0/logout",
		"claims_supported": [
			"sub",
			"iss",
			"cloud_instance_name",
			"cloud_instance_host_name",
			"cloud_graph_host_name",
			"msgraph_host",
			"aud",
			"exp",
			"iat",
			"auth_time",
			"acr",
			"nonce",
			"preferred_username",
			"name",
			"tid",
			"ver",
			"at_hash",
			"c_hash",
			"email"
		],
		"kerberos_endpoint": "{authority}/kerberos",
		"tenant_region_scope": "NA",
		"cloud_instance_name": "microsoftonline.com",
		"cloud_graph_host_name": "graph.windows.net",
		"msgraph_host": "graph.microsoft.com",
		"rbac_url": "https://pas.windows.net"
	}`, "{authority}", authority)
	return []byte(content)
}

const Authnschemeformat = "%s-formated"

type AuthnSchemeTest struct {
}

func (a *AuthnSchemeTest) TokenRequestParams() map[string]string {
	return map[string]string{
		"foo":          "bar",
		"customHeader": "customHeaderValue",
	}
}

func (a *AuthnSchemeTest) KeyID() string {
	return "KeyId"
}

func (a *AuthnSchemeTest) FormatAccessToken(accessToken string) (string, error) {
	return fmt.Sprintf(Authnschemeformat, accessToken), nil
}

func (a *AuthnSchemeTest) AccessTokenType() string {
	return "TokenType"
}

func NewTestAuthnScheme() authority.AuthenticationScheme {
	return &AuthnSchemeTest{}
}

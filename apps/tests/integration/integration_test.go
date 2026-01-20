// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// These tests connect to test apps in a private test tenant the MSAL team has setup.
// The tests will not run on a contributor's dev box, but will run as part of the CI

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

func TestUsernamePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	tests := []struct {
		desc           string
		userSecretName string
	}{
		{"PublicCloud", UserPublicCloud},
		{"Federated", UserFedDefault},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Get user and app config from Key Vault
			user, err := GetUserConfig(test.userSecretName)
			if err != nil {
				t.Fatalf("failed to get user config: %v", err)
			}

			app, err := GetAppConfig(AppPCAClient)
			if err != nil {
				t.Fatalf("failed to get app config: %v", err)
			}

			password, err := user.GetPassword()
			if err != nil {
				t.Fatalf("failed to get password: %v", err)
			}

			// Create public client application
			pca, err := public.New(app.AppID, public.WithAuthority(organizationsAuthority))
			if err != nil {
				t.Fatalf("failed to create public client: %v", err)
			}

			// Acquire token by username/password
			//nolint:staticcheck // SA1019: using deprecated function intentionally
			result, err := pca.AcquireTokenByUsernamePassword(
				context.Background(),
				[]string{graphDefaultScope},
				user.Upn,
				password,
			)
			if err != nil {
				t.Fatalf("AcquireTokenByUsernamePassword() failed: %v", err)
			}

			// Validate results
			if result.AccessToken == "" {
				t.Fatal("got empty AccessToken, want non-empty")
			}
			if result.IDToken.IsZero() {
				t.Fatal("got empty IDToken, want non-empty")
			}
			if result.Account.PreferredUsername != user.Upn {
				t.Fatalf("got Username = %s, want %s", result.Account.PreferredUsername, user.Upn)
			}
		})
	}
}

func TestConfidentialClientWithSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Get app config from Key Vault
	app, err := GetAppConfig(AppS2S)
	if err != nil {
		t.Fatalf("failed to get app config: %v", err)
	}

	// Get the client secret from Key Vault
	// The secret name is stored in the app config's ClientSecret field
	ctx := context.Background()
	secretValue, err := GetSecret(ctx, msalTeamVault, app.SecretName)
	if err != nil {
		t.Fatalf("failed to get client secret: %v", err)
	}

	// Create credential from secret
	cred, err := confidential.NewCredFromSecret(secretValue)
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	// Create confidential client application using authority from config
	authority := app.Authority
	if authority == "" {
		// Fallback to default if not specified in config
		authority = microsoftAuthority
	}
	cca, err := confidential.New(authority, app.AppID, cred)
	if err != nil {
		t.Fatalf("failed to create confidential client: %v", err)
	}

	// Acquire token by credential
	scopes := []string{"https://vault.azure.net/.default"}
	result, err := cca.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() failed: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}
}

func TestOnBehalfOf(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Get user and app config from Key Vault
	user, err := GetUserConfig(UserPublicCloud)
	if err != nil {
		t.Fatalf("failed to get user config: %v", err)
	}

	app, err := GetAppConfig(AppWebAPI)
	if err != nil {
		t.Fatalf("failed to get app config: %v", err)
	}

	password, err := user.GetPassword()
	if err != nil {
		t.Fatalf("failed to get password: %v", err)
	}

	// Get the client secret for the confidential client
	secretValue, err := GetSecret(ctx, msalTeamVault, app.ClientSecret)
	if err != nil {
		t.Fatalf("failed to get client secret: %v", err)
	}

	// Define scopes
	pcaScopes := []string{fmt.Sprintf("api://%s/access_as_user", app.AppID)}
	ccaScopes := []string{graphDefaultScope}

	// 1. An app obtains a token representing a user, for our mid-tier service
	pca, err := public.New(app.AppID, public.WithAuthority(organizationsAuthority))
	if err != nil {
		t.Fatalf("failed to create public client: %v", err)
	}
	//nolint:staticcheck // SA1019: using deprecated function intentionally
	result, err := pca.AcquireTokenByUsernamePassword(
		ctx, pcaScopes, user.Upn, password,
	)
	if err != nil {
		t.Fatalf("AcquireTokenByUsernamePassword() failed: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}

	// 2. Our mid-tier service uses OBO to obtain a token for downstream service
	cred, err := confidential.NewCredFromSecret(secretValue)
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	authority := fmt.Sprintf("%s%s", microsoftAuthorityHost, user.TenantID)
	cca, err := confidential.New(authority, app.AppID, cred)
	if err != nil {
		t.Fatalf("failed to create confidential client: %v", err)
	}

	result1, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, ccaScopes)
	if err != nil {
		t.Fatalf("AcquireTokenOnBehalfOf() failed: %v", err)
	}
	if result1.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}

	// 3. Same scope and assertion should return cached access token
	result2, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, ccaScopes)
	if err != nil {
		t.Fatalf("AcquireTokenOnBehalfOf() (cached) failed: %v", err)
	}
	if result1.AccessToken != result2.AccessToken {
		t.Fatal("cached token doesn't match original token")
	}

	// 4. Different scope should return new token
	scope2 := []string{"https://graph.microsoft.com/user.read"}
	result3, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, scope2)
	if err != nil {
		t.Fatalf("AcquireTokenOnBehalfOf() with different scope failed: %v", err)
	}
	if result3.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}
	if result3.AccessToken == result2.AccessToken {
		t.Fatal("tokens match when they should differ (different scope)")
	}

	// 5. Same scope2 should return cached token
	result4, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, scope2)
	if err != nil {
		t.Fatalf("AcquireTokenOnBehalfOf() (scope2 cached) failed: %v", err)
	}
	if result4.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}
	if result4.AccessToken != result3.AccessToken {
		t.Fatal("cached token doesn't match original token for scope2")
	}

	// 6. New user assertion should return new token
	//nolint:staticcheck // SA1019: using deprecated function intentionally
	result5, err := pca.AcquireTokenByUsernamePassword(
		ctx, pcaScopes, user.Upn, password,
	)
	if err != nil {
		t.Fatalf("AcquireTokenByUsernamePassword() (second call) failed: %v", err)
	}
	result6, err := cca.AcquireTokenOnBehalfOf(ctx, result5.AccessToken, scope2)
	if err != nil {
		t.Fatalf("AcquireTokenOnBehalfOf() with new assertion failed: %v", err)
	}
	if result6.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}
	if result6.AccessToken == result4.AccessToken {
		t.Fatal("tokens match when they should differ (new assertion)")
	}
	if result6.AccessToken == result3.AccessToken {
		t.Fatal("tokens match when they should differ (new assertion vs result3)")
	}
	if result6.AccessToken == result2.AccessToken {
		t.Fatal("tokens match when they should differ (new assertion vs result2)")
	}
}

func TestRemoveAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Get user and app config from Key Vault
	user, err := GetUserConfig(UserPublicCloud)
	if err != nil {
		t.Fatalf("failed to get user config: %v", err)
	}

	app, err := GetAppConfig(AppPCAClient)
	if err != nil {
		t.Fatalf("failed to get app config: %v", err)
	}

	password, err := user.GetPassword()
	if err != nil {
		t.Fatalf("failed to get password: %v", err)
	}

	ctx := context.Background()

	// Create public client application
	pca, err := public.New(app.AppID, public.WithAuthority(organizationsAuthority))
	if err != nil {
		t.Fatalf("failed to create public client: %v", err)
	}

	// Populate the cache
	//nolint:staticcheck // SA1019: using deprecated function intentionally
	_, err = pca.AcquireTokenByUsernamePassword(
		ctx,
		[]string{graphDefaultScope},
		user.Upn,
		password,
	)
	if err != nil {
		t.Fatalf("AcquireTokenByUsernamePassword() failed: %v", err)
	}
	accounts, err := pca.Accounts(ctx)
	if err != nil {
		t.Fatalf("Accounts() failed: %v", err)
	}
	if len(accounts) == 0 {
		t.Fatal("no user accounts found in cache")
	}

	testAccount := accounts[0] // Only one account is populated and that is what we will remove.
	err = pca.RemoveAccount(ctx, testAccount)
	if err != nil {
		t.Fatalf("RemoveAccount() failed: %v", err)
	}

	// Remove Account will clear the cache fields associated with this account so acquire token silent should fail
	_, err = pca.AcquireTokenSilent(ctx, []string{graphDefaultScope}, public.WithSilentAccount(testAccount))
	if err == nil {
		t.Fatal("RemoveAccount() didn't clear the cache as expected")
	}

}

func TestAccountFromCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Get user and app config from Key Vault
	user, err := GetUserConfig(UserPublicCloud)
	if err != nil {
		t.Fatalf("failed to get user config: %v", err)
	}

	app, err := GetAppConfig(AppPCAClient)
	if err != nil {
		t.Fatalf("failed to get app config: %v", err)
	}

	password, err := user.GetPassword()
	if err != nil {
		t.Fatalf("failed to get password: %v", err)
	}

	ctx := context.Background()

	// Create public client application with cache
	pca, err := public.New(app.AppID, public.WithAuthority(organizationsAuthority))
	if err != nil {
		t.Fatalf("failed to create public client: %v", err)
	}

	// Populate the cache with a real token call
	//nolint:staticcheck // SA1019: using deprecated function intentionally
	_, err = pca.AcquireTokenByUsernamePassword(
		ctx,
		[]string{graphDefaultScope},
		user.Upn,
		password,
	)
	if err != nil {
		t.Fatalf("AcquireTokenByUsernamePassword() failed: %v", err)
	}

	// Look in the cache to see if the account has been cached
	var userAccount public.Account
	accounts, err := pca.Accounts(ctx)
	if err != nil {
		t.Fatalf("Accounts() failed: %v", err)
	}
	for _, account := range accounts {
		if account.PreferredUsername == user.Upn {
			userAccount = account
			break
		}
	}
	if userAccount.PreferredUsername == "" {
		t.Fatal("account not found in cache")
	}

	// Acquire token silently from cache
	result, err := pca.AcquireTokenSilent(
		ctx,
		[]string{graphDefaultScope},
		public.WithSilentAccount(userAccount),
	)
	if err != nil {
		t.Fatalf("AcquireTokenSilent() failed: %v", err)
	}
	if result.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}

}

// httpRequestWithRetry performs an HTTP request with simple retry logic for transient failures.
// It retries up to maxRetries times with exponential backoff starting at 1 second.
func httpRequestWithRetry(client *http.Client, req *http.Request, maxRetries int) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s, etc.
			backoff := time.Duration(1<<(attempt-1)) * time.Second
			time.Sleep(backoff)

			// Clone the request for retry (body already consumed on previous attempt)
			req = req.Clone(req.Context())
		}

		resp, err = client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			// Success or client error (4xx) - don't retry
			return resp, nil
		}

		// Log retry attempt
		if err != nil {
			fmt.Printf("HTTP request failed (attempt %d/%d): %v\n", attempt+1, maxRetries+1, err)
		} else {
			// Close the response body before retrying
			resp.Body.Close()
			fmt.Printf("HTTP request returned %d (attempt %d/%d)\n", resp.StatusCode, attempt+1, maxRetries+1)
		}
	}

	return resp, err
}

type urlModifierTransport struct {
	base       http.RoundTripper
	modifyFunc func(*http.Request)
}

// RoundTrip implements the http.RoundTripper interface
func (t *urlModifierTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Modify the request URL for proxying
	if t.modifyFunc != nil {
		t.modifyFunc(req)
	}
	return t.base.RoundTrip(req)
}

func TestAcquireMSITokenExchangeForESTSToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	ctx := context.Background()

	// Configuration matching MSAL .NET ManagedIdentityTests.NetFwk.cs
	const (
		serviceBaseURL = "https://service.msidlab.com/"
		// Resource name with capital 'A' to match .NET
		resource = "api://AzureAdTokenExchange"
		// User Assigned Client ID from .NET test (Consolidated UAMI for both MSI endpoints and Key Vault access)
		userAssignedClientID = "45344e7d-c562-4be6-868f-18dac789c021"
		// Lab Access Client ID for certificate-based authentication
		labAccessClientID = "f62c5ae3-bf3a-4af5-afa8-a68b800396e9"
	)

	// Get access token for service.msidlab.com using certificate auth (same as newLabClient)
	labC, err := newLabClient()
	if err != nil {
		t.Fatal(err)
	}
	labApiAccessToken, err := labC.labAccessToken()
	if err != nil {
		t.Fatalf("Failed to get lab access token: %v", err)
	}

	// Fetch environment variables from service.msidlab.com
	envVarsURL := serviceBaseURL + "EnvironmentVariables?resource=WebApp"
	req, err := http.NewRequestWithContext(ctx, "GET", envVarsURL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+labApiAccessToken)

	resp, err := httpRequestWithRetry(&httpClient, req, 3) // Retry up to 3 times, as the call to service.msidlab.com occasionally times out
	if err != nil {
		t.Fatalf("Failed to get environment variables after retries: %v", err)
	}
	defer resp.Body.Close()

	var envVars map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&envVars); err != nil {
		t.Fatalf("Failed to decode environment variables: %v", err)
	}

	// Set environment variables, modifying IDENTITY_ENDPOINT to point to the proxy
	var originalIdentityEndpoint string
	for key, value := range envVars {
		if key == "IDENTITY_ENDPOINT" {
			originalIdentityEndpoint = value
			value = serviceBaseURL + "MSIToken?azureresource=WebApp&uri=" + value
		}
		t.Setenv(key, value)
	}

	// Create HTTP client that proxies MSI requests through service.msidlab.com
	msiHttpClient := &http.Client{
		Transport: &urlModifierTransport{
			base: http.DefaultTransport,
			modifyFunc: func(req *http.Request) {
				// Build the original URL that would have been called without proxying
				originalURL := originalIdentityEndpoint + "?api-version=2019-08-01&resource=" + url.QueryEscape(resource) + "&client_id=" + userAssignedClientID

				req.URL.Scheme = "https"
				req.URL.Host = "service.msidlab.com"
				req.URL.Path = "/MSIToken"
				req.URL.RawQuery = "azureresource=WebApp&uri=" + url.QueryEscape(originalURL)
				req.Header.Set("Authorization", "Bearer "+labApiAccessToken)
			},
		},
	}

	// Create Managed Identity client
	msiClient, err := managedidentity.New(
		managedidentity.UserAssignedClientID(userAssignedClientID),
		managedidentity.WithHTTPClient(msiHttpClient),
	)
	if err != nil {
		t.Fatalf("Failed to create MSI client: %v", err)
	}

	// Acquire MSI token for token exchange resource
	token, err := msiClient.AcquireToken(ctx, resource)
	if err != nil {
		t.Fatalf("Failed to acquire MSI token: %v", err)
	}
	if token.AccessToken == "" {
		t.Fatal("Expected non-empty MSI access token")
	}

	// Use MSI token as assertion to get ESTS token
	cred := confidential.NewCredFromAssertionCallback(func(ctx context.Context, opt confidential.AssertionRequestOptions) (string, error) {
		msiToken, err := msiClient.AcquireToken(ctx, resource)
		if err != nil {
			return "", fmt.Errorf("failed to acquire MSI token: %w", err)
		}
		return msiToken.AccessToken, nil
	})

	// Create confidential client for token exchange
	confidentialClient, err := confidential.New(
		microsoftAuthority,
		labAccessClientID,
		cred,
		confidential.WithInstanceDiscovery(false),
	)
	if err != nil {
		t.Fatalf("Failed to create confidential client: %v", err)
	}

	// Exchange MSI token for ESTS token (Key Vault access)
	scopes := []string{"https://msidlabs.vault.azure.net/.default"}
	authResult, err := confidentialClient.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("Failed to exchange MSI token for ESTS token: %v", err)
	}
	if authResult.AccessToken == "" {
		t.Fatal("Expected non-empty ESTS access token")
	}
	if authResult.Metadata.TokenSource != base.TokenSourceIdentityProvider {
		t.Fatalf("Expected token source 'IdentityProvider', got '%d'", authResult.Metadata.TokenSource)
	}

	// Second call should return cached token
	authResult, err = confidentialClient.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("Failed to acquire cached ESTS token: %v", err)
	}
	if authResult.AccessToken == "" {
		t.Fatal("Expected non-empty cached ESTS access token")
	}
	if authResult.Metadata.TokenSource != base.TokenSourceCache {
		t.Fatalf("Expected token source 'Cache', got '%d'", authResult.Metadata.TokenSource)
	}
}

func TestAdfsToken(t *testing.T) {
	t.Skip("skipping ADFS tests")

	cert, privateKey, err := getCertDataFromFile(ccaPemFile)
	if err != nil {
		t.Fatalf("failed to load cert: %v", err)
	}

	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	app, err := confidential.New("https://fs.msidlab8.com/adfs", "ConfidentialClientId", cred)
	if err != nil {
		t.Fatalf("failed to create confidential client: %v", err)
	}

	result, err := app.AcquireTokenByCredential(context.Background(), []string{"openid"})
	if err != nil {
		t.Fatalf("AcquireTokenByCredential() failed: %v", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("got empty AccessToken, want non-empty")
	}
}

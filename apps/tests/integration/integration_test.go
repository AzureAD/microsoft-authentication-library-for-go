// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// These tests connect to test apps in a private test tenant the MSAL team has setup.
// The tests will not run on a contributor's dev box, but will run as part of the CI

package integration

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	// URLS
	msIDlabDefaultScope    = "https://request.msidlab.com/.default"
	graphDefaultScope      = "https://graph.windows.net/.default"
	microsoftAuthorityHost = "https://login.microsoftonline.com/"

	organizationsAuthority = microsoftAuthorityHost + "organizations/"
	microsoftAuthority     = microsoftAuthorityHost + "72f988bf-86f1-41af-91ab-2d7cd011db47"
	//msIDlabTenantAuthority = microsoftAuthorityHost + "msidlab4.onmicrosoft.com" - Will be needed in the future
	msiClientId = "4b7a4b0b-ecb2-409e-879a-1e21a15ddaf6"
	// Default values
	defaultClientId = "f62c5ae3-bf3a-4af5-afa8-a68b800396e9"
	pemFile         = "../../../cert.pem"
	ccaPemFile      = "../../../ccaCert.pem"
)

var httpClient = http.Client{}

func httpRequest(ctx context.Context, url string, query url.Values, accessToken string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build new http request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.URL.RawQuery = query.Encode()
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s) failed: %w", req.URL.String(), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s): could not read body: %w", req.URL.String(), err)
	}
	return body, nil
}

type labClient struct {
	app confidential.Client
}

// TODO : Add app object

type user struct {
	AppID            string `json:"appId"`
	ObjectID         string `json:"objectId"`
	UserType         string `json:"userType"`
	DisplayName      string `json:"displayName"`
	Licenses         string `json:"licences"`
	Upn              string `json:"upn"`
	Mfa              string `json:"mfa"`
	ProtectionPolicy string `json:"protectionPolicy"`
	HomeDomain       string `json:"homeDomain"`
	HomeUPN          string `json:"homeUPN"`
	B2cProvider      string `json:"b2cProvider"`
	LabName          string `json:"labName"`
	LastUpdatedBy    string `json:"lastUpdatedBy"`
	LastUpdatedDate  string `json:"lastUpdatedDate"`
	Password         string
}

type secret struct {
	Value string `json:"value"`
}

func newLabClient() (*labClient, error) {
	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("Could not get cert data: %w", err)
	}

	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("Could not create a cred from the cert: %w", err)
	}

	app, err := confidential.New(microsoftAuthority, defaultClientId, cred, confidential.WithX5C())
	if err != nil {
		return nil, err
	}

	return &labClient{app: app}, nil
}

func getCertDataFromFile(filePath string) ([]*x509.Certificate, crypto.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Error finding certificate: %v\n", err)
	}

	cert, privateKey, err := confidential.CertFromPEM(data, "")

	if err != nil {
		fmt.Printf("Error finding certificate: %v\n", err)
	}

	return cert, privateKey, nil
}

func (l *labClient) labAccessToken() (string, error) {
	scopes := []string{msIDlabDefaultScope}
	result, err := l.app.AcquireTokenSilent(context.Background(), scopes)
	if err != nil {
		result, err = l.app.AcquireTokenByCredential(context.Background(), scopes)
		if err != nil {
			return "", fmt.Errorf("AcquireTokenByCredential() error: %w", err)
		}
	}
	return result.AccessToken, nil
}

func (l *labClient) getLabResponse(url string, query url.Values) (string, error) {
	accessToken, err := l.labAccessToken()
	if err != nil {
		return "", fmt.Errorf("problem getting lab access token: %w", err)
	}
	responseBody, err := httpRequest(context.Background(), url, query, accessToken)
	if err != nil {
		return "", err
	}
	return string(responseBody), nil
}

func (l *labClient) user(ctx context.Context, query url.Values) (user, error) {
	accessToken, err := l.labAccessToken()
	if err != nil {
		return user{}, fmt.Errorf("problem getting lab access token: %w", err)
	}

	responseBody, err := httpRequest(ctx, "https://msidlab.com/api/user", query, accessToken)
	if err != nil {
		return user{}, err
	}

	var users []user
	err = json.Unmarshal(responseBody, &users)
	if err != nil {
		return user{}, err
	}
	if len(users) == 0 {
		return user{}, errors.New("No user found")
	}
	user := users[0]
	user.Password, err = l.secret(ctx, url.Values{"Secret": []string{user.LabName}})
	if err != nil {
		return user, err
	}
	return user, nil
}

func (l *labClient) secret(ctx context.Context, query url.Values) (string, error) {
	accessToken, err := l.labAccessToken()
	if err != nil {
		return "", err
	}
	responseBody, err := httpRequest(ctx, "https://msidlab.com/api/LabSecret", query, accessToken)
	if err != nil {
		return "", err
	}
	var secret secret
	err = json.Unmarshal(responseBody, &secret)
	if err != nil {
		return "", err
	}
	return secret.Value, nil
}

// TODO: Add getApp() when needed

func testUser(ctx context.Context, desc string, lc *labClient, query url.Values) user {
	testUser, err := lc.user(ctx, query)
	if err != nil {
		panic(fmt.Sprintf("TestUsernamePassword(%s) setup: testUser(): Failed to get input user: %s", desc, err))
	}
	return testUser
}

func TestUsernamePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	labClientInstance, err := newLabClient()
	if err != nil {
		panic("failed to get a lab client: " + err.Error())
	}

	tests := []struct {
		desc string
		vals url.Values
	}{
		{"ADFSv4", url.Values{"usertype": []string{"federated"}, "federationProvider": []string{"ADFSv4"}}},
	}
	for _, test := range tests {
		ctx := context.Background()

		user := testUser(ctx, test.desc, labClientInstance, test.vals)
		app, err := public.New(user.AppID, public.WithAuthority(organizationsAuthority))
		if err != nil {
			panic(errors.Verbose(err))
		}
		result, err := app.AcquireTokenByUsernamePassword(
			context.Background(),
			[]string{graphDefaultScope},
			user.Upn,
			user.Password,
		)
		if err != nil {
			t.Fatalf("TestUsernamePassword(%s): on AcquireTokenByUsernamePassword(): got err == %s, want err == nil", test.desc, errors.Verbose(err))
		}
		if result.AccessToken == "" {
			t.Fatalf("TestUsernamePassword(%s): got AccessToken == '', want AccessToken != ''", test.desc)
		}
		if result.IDToken.IsZero() {
			t.Fatalf("TestUsernamePassword(%s): got IDToken == empty, want IDToken == non-empty struct", test.desc)
		}
		if result.Account.PreferredUsername != user.Upn {
			t.Fatalf("TestUsernamePassword(%s): got Username == %s, want Username == %s", test.desc, result.Account.PreferredUsername, user.Upn)
		}
	}
}

// TODO: update this at a later date, see issue https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/513
func TestConfidentialClientWithSecret(t *testing.T) {
	t.Skip("Skipping test until fix")
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	clientID := os.Getenv("clientId")
	secret := os.Getenv("clientSecret")
	cred, err := confidential.NewCredFromSecret(secret)
	if err != nil {
		panic(errors.Verbose(err))
	}

	app, err := confidential.New(microsoftAuthority, clientID, cred)
	if err != nil {
		panic(errors.Verbose(err))
	}
	scopes := []string{msIDlabDefaultScope}
	result, err := app.AcquireTokenByCredential(context.Background(), scopes)
	if err != nil {
		t.Fatalf("TestConfidentialClientwithSecret: on AcquireTokenByCredential(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestConfidentialClientwithSecret: on AcquireTokenByCredential(): got AccessToken == '', want AccessToken != ''")
	}
	silentResult, err := app.AcquireTokenSilent(context.Background(), scopes)
	if err != nil {
		t.Fatalf("TestConfidentialClientwithSecret: on AcquireTokenSilent(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if silentResult.AccessToken == "" {
		t.Fatal("TestConfidentialClientwithSecret: on AcquireTokenSilent(): got AccessToken == '', want AccessToken != ''")
	}
}

// TODO: update this at a later date, see issue https://github.com/AzureAD/microsoft-authentication-library-for-go/issues/513
func TestOnBehalfOf(t *testing.T) {
	t.Skip("Skipping test until fix")
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	labClientInstance, err := newLabClient()
	if err != nil {
		panic("failed to get a lab client: " + err.Error())
	}

	ctx := context.Background()

	//Confidential Client Application Config
	ccaClientID := os.Getenv("oboConfidentialClientId")
	ccaClientSecret := os.Getenv("oboConfidentialClientSecret")
	ccaScopes := []string{"https://graph.microsoft.com/user.read"}

	// Public Client Application Confifg
	pcaClientID := os.Getenv("oboPublicClientId")
	user := testUser(ctx, "OnBehalfOf", labClientInstance, url.Values{"usertype": []string{"cloud"}})
	pcaScopes := []string{fmt.Sprintf("api://%s/.default", ccaClientID)}

	// 1. An app obtains a token representing a user, for our mid-tier service
	pca, err := public.New(pcaClientID, public.WithAuthority(organizationsAuthority))
	if err != nil {
		panic(errors.Verbose(err))
	}
	result, err := pca.AcquireTokenByUsernamePassword(
		ctx, pcaScopes, user.Upn, user.Password,
	)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenByUsernamePassword(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestOnBehalfOf: on AcquireTokenByUsernamePassword(): got AccessToken == '', want AccessToken != ''")
	}

	// 2. Our mid-tier service uses OBO to obtain a token for downstream service
	cred, err := confidential.NewCredFromSecret(ccaClientSecret)
	if err != nil {
		panic(errors.Verbose(err))
	}
	cca, err := confidential.New("https://login.microsoftonline.com/common", ccaClientID, cred)
	if err != nil {
		panic(errors.Verbose(err))
	}
	result1, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, ccaScopes)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result1.AccessToken == "" {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got AccessToken == '', want AccessToken != ''")
	}

	// 3. Same scope and assertion should return cached access token
	result2, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, ccaScopes)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenOnBehalfOf() silent token retrieval: got err == %s, want err == nil", errors.Verbose(err))
	}
	if result1.AccessToken != result2.AccessToken {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): Access Tokens don't match")
	}

	// 4. scope2 should return new token
	scope2 := []string{"https://graph.windows.net/.default"}
	result3, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, scope2)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result3.AccessToken == "" {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got AccessToken == '', want AccessToken != ''")
	}
	if result3.AccessToken == result2.AccessToken {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): Access Tokens match when they should not")
	}

	// 5. scope2 should return cached token
	result4, err := cca.AcquireTokenOnBehalfOf(ctx, result.AccessToken, scope2)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result4.AccessToken == "" {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got AccessToken == '', want AccessToken != ''")
	}
	if result4.AccessToken != result3.AccessToken {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): Access Tokens don't match")
	}

	// 6. New user assertion should return new token
	pca1, err := public.New(pcaClientID, public.WithAuthority(organizationsAuthority))
	if err != nil {
		panic(errors.Verbose(err))
	}
	result5, err := pca1.AcquireTokenByUsernamePassword(
		ctx, pcaScopes, user.Upn, user.Password,
	)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenByUsernamePassword(): got err == %s, want err == nil", errors.Verbose(err))
	}
	result6, err := cca.AcquireTokenOnBehalfOf(ctx, result5.AccessToken, scope2)
	if err != nil {
		t.Fatalf("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result6.AccessToken == "" {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): got AccessToken == '', want AccessToken != ''")
	}
	if result6.AccessToken == result4.AccessToken {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): Access Tokens match when they should not")
	}
	if result6.AccessToken == result3.AccessToken {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): Access Tokens match when they should not")
	}
	if result6.AccessToken == result2.AccessToken {
		t.Fatal("TestOnBehalfOf: on AcquireTokenOnBehalfOf(): Access Tokens match when they should not")
	}
}

func TestRemoveAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	labClientInstance, err := newLabClient()
	if err != nil {
		panic("failed to get a lab client: " + err.Error())
	}
	ctx := context.Background()

	user := testUser(ctx, "TestRemoveAccount", labClientInstance, url.Values{"usertype": []string{"cloud"}})
	app, err := public.New(user.AppID, public.WithAuthority(organizationsAuthority))
	if err != nil {
		panic(errors.Verbose(err))
	}
	// Populate the cache
	_, err = app.AcquireTokenByUsernamePassword(
		context.Background(),
		[]string{graphDefaultScope},
		user.Upn,
		user.Password,
	)
	if err != nil {
		t.Fatalf("TestRemoveAccount: on AcquireTokenByUsernamePassword(): got err == %s, want err == nil", errors.Verbose(err))
	}
	accounts, err := app.Accounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(accounts) == 0 {
		t.Fatal("TestRemoveAccount: No user accounts found in cache")
	}
	testAccount := accounts[0] // Only one account is populated and that is what we will remove.
	err = app.RemoveAccount(ctx, testAccount)
	if err != nil {
		t.Fatalf("TestRemoveAccount: on RemoveAccount(): got err == %s, want err == nil", errors.Verbose(err))
	}
	// Remove Account will clear the cache fields associated with this account so acquire token silent should fail
	_, err = app.AcquireTokenSilent(ctx, []string{graphDefaultScope}, public.WithSilentAccount(testAccount))
	if err == nil {
		t.Fatal("TestRemoveAccount: RemoveAccount() didn't clear the cache as expected")
	}

}

const testCacheFile = "serialized_cache_1.1.1.json"

func TestAccountFromCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	cacheAccessor := &TokenCache{file: testCacheFile}
	labClientInstance, err := newLabClient()
	if err != nil {
		t.Fatalf("TestAccountFromCache: on newLabClient(): got err == %s, want err == nil", errors.Verbose(err))
	}
	ctx := context.Background()
	user := testUser(ctx, "Managed", labClientInstance, url.Values{"usertype": []string{"cloud"}})

	app, err := public.New(user.AppID, public.WithAuthority(organizationsAuthority), public.WithCache(cacheAccessor))
	if err != nil {
		t.Fatalf("TestAccountFromCache: on New(): got err == %s, want err == nil", errors.Verbose(err))
	}

	// look in the cache to see if the account to use has been cached
	var userAccount public.Account
	accounts, err := app.Accounts(ctx)
	if err != nil {
		t.Fatalf("TestAccountFromCache: on Accounts(): got err == %s, want err == nil", errors.Verbose(err))
	}
	for _, account := range accounts {
		if account.PreferredUsername == user.Upn {
			userAccount = account
		}
	}
	result, err := app.AcquireTokenSilent(
		ctx,
		[]string{graphDefaultScope},
		public.WithSilentAccount(userAccount),
	)
	if err != nil {
		t.Fatalf("TestAccountFromCache: on AcquireTokenSilent(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestAccountFromCache: on AcquireTokenSilent(): got AccessToken == '', want AccessToken != ''")
	}

}

type urlModifierTransport struct {
	base       http.RoundTripper
	modifyFunc func(*http.Request)
}

// RoundTrip implements the http.RoundTripper interface
func (t *urlModifierTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Modifying the original resquest to have the updated URL
	if t.modifyFunc != nil {
		t.modifyFunc(req)
	}
	return t.base.RoundTrip(req)
}

func TestAcquireMSITokenExchangeForESTSToken(t *testing.T) {
	labC, err := newLabClient()
	if err != nil {
		t.Fatal(err)
	}
	baseUrl := "https://service.msidlab.com/"
	resource := "api://azureadtokenexchange"
	query := url.Values{}
	query.Add("resource", "WebApp")
	response, err := labC.getLabResponse(baseUrl+"EnvironmentVariables", query)
	if err != nil {
		t.Fatalf("Failed to get resource env variable: %v", err)
	}
	var result map[string]string
	err = json.Unmarshal([]byte(response), &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	for key, value := range result {
		if key == "IDENTITY_ENDPOINT" {
			value = "https://service.msidlab.com/MSIToken?azureresource=WebApp&uri=" + value
		}
		t.Setenv(key, value)
	}
	// Replace your existing http.Client with this one
	httpClient := http.Client{
		Transport: &urlModifierTransport{
			base: http.DefaultTransport,
			modifyFunc: func(req *http.Request) {
				req.URL.Host = "service.msidlab.com"
				req.URL.Path = "/MSIToken"
				req.URL.Scheme = "https"
				req.URL.RawQuery = "azureresource=WebApp&uri=http%3A%2F%2F127.0.0.1%3A41488%2Fmsi%2Ftoken%2F%3Fapi-version%3D2019-08-01%26resource%3Dapi%3A%2F%2Fazureadtokenexchange%26client_id%3D" + msiClientId
				accessToken, err := labC.labAccessToken()
				if err != nil {
					t.Fatal("Failed to get access token: ", err)
				}
				req.Header.Set("Authorization", "Bearer "+accessToken)
			},
		},
	}
	ctx := context.Background()
	msiClient, err := managedidentity.New(managedidentity.UserAssignedClientID(msiClientId),
		managedidentity.WithHTTPClient(&httpClient))
	if err != nil {
		t.Fatalf("Failed to create MSI client: %v", err)
	}
	token, err := msiClient.AcquireToken(ctx, resource)
	if err != nil {
		t.Fatalf("Failed to acquire token: %v", err)
	}
	if token.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}
	cred := confidential.NewCredFromAssertionCallback(func(ctx context.Context, opt confidential.AssertionRequestOptions) (string, error) {
		token, err := msiClient.AcquireToken(ctx, resource)
		if err != nil {
			t.Fatalf("Failed to acquire token: %v", err)
		}
		return token.AccessToken, nil
	})
	confidentialClient, err := confidential.New(microsoftAuthority,
		defaultClientId,
		cred,
		confidential.WithInstanceDiscovery(false))
	if err != nil {
		t.Fatalf("Failed to create confidential client: %v", err)
	}

	authResult, err := confidentialClient.AcquireTokenByCredential(ctx, []string{"https://msidlabs.vault.azure.net/.default"})
	if err != nil {
		t.Fatalf("Failed to acquire token by credential: %v", err)
	}
	if authResult.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}
	if authResult.Metadata.TokenSource != base.TokenSourceIdentityProvider {
		t.Fatalf("Expected token source 'IdentityProvider', got '%d'", authResult.Metadata.TokenSource)
	}
	authResult, err = confidentialClient.AcquireTokenSilent(ctx, []string{"https://msidlabs.vault.azure.net/.default"})
	if err != nil {
		t.Fatalf("Failed to acquire token by credential: %v", err)
	}
	if authResult.AccessToken == "" {
		t.Fatal("Expected non-empty access token")
	}
	if authResult.Metadata.TokenSource != base.TokenSourceCache {
		t.Fatalf("Expected token source 'Cache', got '%d'", authResult.Metadata.TokenSource)
	}
}

func TestAdfsToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	cert, privateKey, err := getCertDataFromFile(ccaPemFile)
	if err != nil {
		t.Fatal("Could not get cert data: %w", err)
	}

	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	app, err := confidential.New("https://fs.msidlab8.com/adfs", "ConfidentialClientId", cred)
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{"openid"}
	result, err := app.AcquireTokenByCredential(context.Background(), scopes)
	if err != nil {
		t.Fatalf("TestConfidentialClientwithSecret: on AcquireTokenByCredential(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestConfidentialClientwithSecret: on AcquireTokenByCredential(): got AccessToken == '', want AccessToken != ''")
	}
}

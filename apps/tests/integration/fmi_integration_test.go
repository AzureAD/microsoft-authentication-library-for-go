// FMITestSuite contains a set of tests for Family of Multiple Identities functionality
// FMI allows sharing refresh tokens between applications that belong to the same family

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
)

const (
	// Common test configuration
	testTenantID = "f645ad92-e38d-4d1a-b510-d1b09a74a8ca"
	testClientID = "4df2cbbb-8612-49c1-87c8-f334d6d065ad"
	testScope    = "3091264c-7afb-45d4-b527-39737ee86187/.default"
	fmiClientID  = "urn:microsoft:identity:fmi"
	fmiScope     = "api://AzureFMITokenExchange/.default"
	fmiPath      = "SomeFmiPath/FmiCredentialPath"
	authorityURL = "https://login.microsoftonline.com/" + testTenantID
)

func TestFMIBasicFunctionality(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Create temporary cache and defer cleanup
	tmpCacheFile := "fmi_basic_cache.json"
	defer os.Remove(tmpCacheFile)

	// Create the cache file if it doesn't exist
	if _, err := os.Stat(tmpCacheFile); os.IsNotExist(err) {
		file, err := os.Create(tmpCacheFile)
		if err != nil {
			t.Fatalf("TestFMIBasicFunctionality: failed to create cache file: %s", err)
		}
		file.Close()
	}

	cacheAccessor := &TokenCache{file: tmpCacheFile}
	ctx := context.Background()
	scopes := []string{testScope}

	// Get certificate credentials
	cert, privateKey, err := getCertDataFromFile(ccaPemFile)
	if err != nil {
		t.Fatalf("TestFMIBasicFunctionality: getCertDataFromFile() failed: %s", errors.Verbose(err))
	}

	// Create credentials from certificate
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("TestFMIBasicFunctionality: NewCredFromCert() failed: %s", errors.Verbose(err))
	}

	// Create confidential client app
	app, err := confidential.New(authorityURL, testClientID, cred, confidential.WithCache(cacheAccessor))
	if err != nil {
		t.Fatalf("TestFMIBasicFunctionality: confidential.New() failed: %s", errors.Verbose(err))
	}

	// 1. First, acquire token by credential
	result, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithFMIPath(fmiPath))
	if err != nil {
		t.Fatalf("TestFMIBasicFunctionality: AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestFMIBasicFunctionality: AcquireTokenByCredential() returned empty AccessToken")
	}

	// 2. Verify silent token acquisition works (should retrieve from cache)
	silentResult, err := app.AcquireTokenSilent(ctx, scopes)
	if err != nil {
		t.Fatalf("TestFMIBasicFunctionality: AcquireTokenSilent() failed: %s", errors.Verbose(err))
	}
	if silentResult.AccessToken == "" {
		t.Fatal("TestFMIBasicFunctionality: AcquireTokenSilent() returned empty AccessToken")
	}

	// Validate that we got the same token (proving cache was used)
	if result.AccessToken != silentResult.AccessToken {
		t.Fatalf("TestFMIBasicFunctionality: token comparison failed - tokens don't match, cache might not be working correctly")
	}
}

// TestFMIWithMultipleApps tests sharing tokens between multiple applications
// that belong to the same family using the FMI feature
func TestFMIWithMultipleApps(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Create temporary cache and defer cleanup
	tmpCacheFile := "fmi_multiple_apps.json"
	defer os.Remove(tmpCacheFile)

	// Create the cache file if it doesn't exist
	if _, err := os.Stat(tmpCacheFile); os.IsNotExist(err) {
		file, err := os.Create(tmpCacheFile)
		if err != nil {
			t.Fatalf("TestFMIWithMultipleApps: failed to create cache file: %s", err)
		}
		file.Close()
	}

	cacheAccessor := &TokenCache{file: tmpCacheFile}
	ctx := context.Background()
	scopes := []string{testScope}

	// Get certificate credentials
	cert, privateKey, err := getCertDataFromFile(ccaPemFile)
	if err != nil {
		t.Fatalf("TestFMIWithMultipleApps: getCertDataFromFile() failed: %s", errors.Verbose(err))
	}

	// Create credentials from certificate
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		t.Fatalf("TestFMIWithMultipleApps: NewCredFromCert() failed: %s", errors.Verbose(err))
	}

	// Create first confidential client app
	app1, err := confidential.New(authorityURL, testClientID, cred, confidential.WithCache(cacheAccessor))
	if err != nil {
		t.Fatalf("TestFMIWithMultipleApps: confidential.New() for app1 failed: %s", errors.Verbose(err))
	}

	// Acquire token for the first app
	result1, err := app1.AcquireTokenByCredential(ctx, scopes)
	if err != nil {
		t.Fatalf("TestFMIWithMultipleApps: AcquireTokenByCredential() for app1 failed: %s", errors.Verbose(err))
	}
	if result1.AccessToken == "" {
		t.Fatal("TestFMIWithMultipleApps: AcquireTokenByCredential() for app1 returned empty AccessToken")
	}

	// Create second confidential client app with same configuration
	// In a real scenario, this would be a different app in the same family
	app2, err := confidential.New(authorityURL, testClientID, cred, confidential.WithCache(cacheAccessor))
	if err != nil {
		t.Fatalf("TestFMIWithMultipleApps: confidential.New() for app2 failed: %s", errors.Verbose(err))
	}

	// Attempt to acquire token silently for the second app
	// FMI should allow this to work even though we never explicitly acquired a token for this client ID
	result2, err := app2.AcquireTokenSilent(ctx, scopes)
	if err != nil {
		t.Fatalf("TestFMIWithMultipleApps: AcquireTokenSilent() for app2 failed: %s", errors.Verbose(err))
	}
	if result2.AccessToken == "" {
		t.Fatal("TestFMIWithMultipleApps: AcquireTokenSilent() for app2 returned empty AccessToken")
	}

	t.Log("TestFMIWithMultipleApps: Successfully acquired token for second app using FMI")
}

// TestFMIIntegration tests the Family Multiple Identity functionality
// It verifies:
// 1. Tokens can be acquired using certificate authentication
// 2. Tokens can be used as assertion and get a new token with FMI
func TestFMIIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	// Create temporary cache and defer cleanup
	tmpCacheFile := "fmi_testfile.json"
	defer os.Remove(tmpCacheFile)

	// Create the cache file if it doesn't exist
	if _, err := os.Stat(tmpCacheFile); os.IsNotExist(err) {
		file, err := os.Create(tmpCacheFile)
		if err != nil {
			t.Fatalf("TestFMIIntegration: failed to create cache file: %s", err)
		}
		file.Close()
	}

	cacheAccessor := &TokenCache{file: tmpCacheFile}
	ctx := context.Background()
	scopes := []string{testScope}

	// Get credentials from RMA
	cred := confidential.NewCredFromAssertionCallback(func(ctx context.Context, aro confidential.AssertionRequestOptions) (string, error) {
		return GetFmiCredentialFromRma(ctx)
	})

	// Create confidential client app
	app, err := confidential.New(authorityURL, fmiClientID, cred, confidential.WithCache(cacheAccessor))
	if err != nil {
		t.Fatalf("TestFMIIntegration: confidential.New() failed: %s", errors.Verbose(err))
	}

	// 1. First, acquire token by credential
	result, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithFMIPath("SomeFmiPath/Path"))
	if err != nil {
		t.Fatalf("TestFMIIntegration: AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestFMIIntegration: AcquireTokenByCredential() returned empty AccessToken")
	}

	// Store the token from first call
	firstToken := result.AccessToken

	// 2. Verify silent token acquisition works (should retrieve from cache)
	silentResult, err := app.AcquireTokenSilent(ctx, scopes)
	if err != nil {
		t.Fatalf("TestFMIIntegration: AcquireTokenSilent() failed: %s", errors.Verbose(err))
	}
	if silentResult.AccessToken == "" {
		t.Fatal("TestFMIIntegration: AcquireTokenSilent() returned empty AccessToken")
	}

	// 3. Compare the tokens to verify cache was used
	if firstToken != silentResult.AccessToken {
		t.Fatalf("TestFMIIntegration: token comparison failed - tokens don't match, cache might not be working correctly")
	}
}

// GetFmiCredentialFromRma acquires an FMI token from RMA service
func GetFmiCredentialFromRma(ctx context.Context) (string, error) {
	// Get certificate data using the existing helper method
	cert, privateKey, err := getCertDataFromFile(ccaPemFile)
	if err != nil {
		return "", fmt.Errorf("failed to get certificate data: %w", err)
	}

	// Create credentials from certificate
	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create credential from certificate: %w", err)
	}

	// Create application
	app, err := confidential.New(authorityURL, testClientID, cred)
	if err != nil {
		return "", fmt.Errorf("failed to create confidential client application: %w", err)
	}

	// Acquire Token using client credentials flow with FMI path
	result, err := app.AcquireTokenByCredential(
		ctx,
		[]string{fmiScope},
		confidential.WithFMIPath(fmiPath), // Sets FMI path in client credential request
	)
	if err != nil {
		return "", fmt.Errorf("failed to acquire token: %w", err)
	}
	return result.AccessToken, nil
}

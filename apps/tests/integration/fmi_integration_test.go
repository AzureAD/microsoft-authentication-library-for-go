// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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
	// Common test configuration - matches MSAL .NET FmiIntegrationTests
	testTenantID = "10c419d4-4a50-45b2-aa4e-919fb84df24f"
	testClientID = "3bf56293-fbb5-42bd-a407-248ba7431a8c"
	testScope    = "api://aa464f73-2868-4f67-b0e7-fc2f749e757f/.default"
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

	// Get certificate credentials (LabAuth cert, matching MSAL .NET)
	cert, privateKey, err := getCertDataFromFile(pemFile)
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
	cacheToken, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithFMIPath(fmiPath))
	if err != nil {
		t.Fatalf("TestFMIBasicFunctionality: AcquireTokenSilent() failed: %s", errors.Verbose(err))
	}
	if cacheToken.AccessToken == "" {
		t.Fatal("TestFMIBasicFunctionality: AcquireTokenSilent() returned empty AccessToken")
	}
	if cacheToken.Metadata.TokenSource != confidential.TokenSourceCache {
		t.Fatalf("TestFMIBasicFunctionality: AcquireTokenSilent() did not return token from cache")
	}
	// Validate that we got the same token (proving cache was used)
	if result.AccessToken != cacheToken.AccessToken {
		t.Fatalf("TestFMIBasicFunctionality: token comparison failed - tokens don't match, cache might not be working correctly")
	}
}

// TestFMIIntegration tests the Federated Managed Identity functionality
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

	// 2. Verify AcquireTokenByCredential acquisition works (should retrieve from cache)
	cacheToken, err := app.AcquireTokenByCredential(ctx, scopes, confidential.WithFMIPath("SomeFmiPath/Path"))
	if err != nil {
		t.Fatalf("TestFMIIntegration: AcquireTokenByCredential() failed: %s", errors.Verbose(err))
	}
	if cacheToken.AccessToken == "" {
		t.Fatal("TestFMIIntegration: AcquireTokenByCredential() returned empty AccessToken")
	}
	if cacheToken.Metadata.TokenSource != confidential.TokenSourceCache {
		t.Fatalf("TestFMIIntegration: AcquireTokenByCredential() did not return token from cache")
	}

	// 3. Compare the tokens to verify cache was used
	if firstToken != cacheToken.AccessToken {
		t.Fatalf("TestFMIIntegration: token comparison failed - tokens don't match, cache might not be working correctly")
	}
}

// GetFmiCredentialFromRma acquires an FMI token from RMA service
func GetFmiCredentialFromRma(ctx context.Context) (string, error) {
	// Get certificate data using the existing helper method (LabAuth cert, matching MSAL .NET)
	cert, privateKey, err := getCertDataFromFile(pemFile)
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

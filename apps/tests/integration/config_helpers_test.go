// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// Key Vault URLs
const (
	msidLabVault  = "https://msidlabs.vault.azure.net"
	msalTeamVault = "https://id4skeyvault.vault.azure.net"
)

// Authentication constants
const (
	microsoftAuthorityHost = "https://login.microsoftonline.com/"
	microsoftAuthority     = microsoftAuthorityHost + "microsoft.onmicrosoft.com"
	organizationsAuthority = microsoftAuthorityHost + "organizations/"

	msIDlabDefaultScope = "https://request.msidlab.com/.default"
	graphDefaultScope   = "https://graph.windows.net/.default"

	defaultClientId = "f62c5ae3-bf3a-4af5-afa8-a68b800396e9"

	pemFile    = "../../../cert.pem"
	ccaPemFile = "../../../ccaCert.pem"
)

// Key Vault secret names - user configs
const (
	UserPublicCloud = "User-PublicCloud-Config"
	UserFedDefault  = "User-Federated-Config"
	UserB2C         = "MSAL-USER-B2C-JSON"
	UserArlington   = "MSAL-USER-Arlington-JSON"
	UserCIAM        = "MSAL-USER-CIAM-JSON"
)

// Key Vault secret names - app configs
const (
	AppPCAClient = "App-PCAClient-Config"
	AppWebAPI    = "App-WebAPI-Config"
	AppS2S       = "App-S2S-Config"
)

// UserConfig represents user configuration from Key Vault
type UserConfig struct {
	AppID              string `json:"appId,omitempty"`
	ObjectID           string `json:"objectId,omitempty"`
	UserType           string `json:"userType,omitempty"`
	DisplayName        string `json:"displayName,omitempty"`
	Licenses           string `json:"licenses,omitempty"`
	Upn                string `json:"upn,omitempty"`
	MFA                string `json:"mfa,omitempty"`
	ProtectionPolicy   string `json:"protectionPolicy,omitempty"`
	HomeDomain         string `json:"homeDomain,omitempty"`
	HomeUPN            string `json:"homeUPN,omitempty"`
	B2CProvider        string `json:"b2cProvider,omitempty"`
	LabName            string `json:"labName,omitempty"`
	LastUpdatedBy      string `json:"lastUpdatedBy,omitempty"`
	LastUpdatedDate    string `json:"lastUpdatedDate,omitempty"`
	TenantID           string `json:"tenantId,omitempty"`
	FederationProvider string `json:"federationProvider,omitempty"`
	password           string // cached password, fetched lazily
}

// AppConfig represents app configuration from Key Vault
type AppConfig struct {
	AppType      string `json:"appType,omitempty"`
	AppName      string `json:"appName,omitempty"`
	AppID        string `json:"appId,omitempty"`
	RedirectURI  string `json:"redirectUri,omitempty"`
	Authority    string `json:"authority,omitempty"`
	LabName      string `json:"labName,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	SecretName   string `json:"secretName,omitempty"`
}

// labResponse is the container for JSON from Key Vault
type labResponse struct {
	User *UserConfig `json:"user,omitempty"`
	App  *AppConfig  `json:"app,omitempty"`
}

// Package-level cache and Key Vault clients
var (
	userCache = make(map[string]*UserConfig)
	appCache  = make(map[string]*AppConfig)
	cacheMu   sync.RWMutex

	msidClient   confidential.Client
	msalClient   confidential.Client
	clientInitMu sync.Once

	httpClient = http.Client{}
)

type labClient struct {
	app confidential.Client
}

func newLabClient() (*labClient, error) {
	cert, privateKey, err := getCertDataFromFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("could not get cert data: %w", err)
	}

	cred, err := confidential.NewCredFromCert(cert, privateKey)
	if err != nil {
		return nil, fmt.Errorf("could not create a cred from the cert: %w", err)
	}

	app, err := confidential.New(microsoftAuthority, defaultClientId, cred, confidential.WithX5C())
	if err != nil {
		return nil, err
	}

	return &labClient{app: app}, nil
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

// initKeyVaultClients initializes the Key Vault access clients using cert auth
func initKeyVaultClients() error {
	var initErr error
	clientInitMu.Do(func() {
		cert, privateKey, err := getCertDataFromFile(pemFile)
		if err != nil {
			initErr = fmt.Errorf("failed to load cert: %w", err)
			return
		}

		cred, err := confidential.NewCredFromCert(cert, privateKey)
		if err != nil {
			initErr = fmt.Errorf("failed to create cert credential: %w", err)
			return
		}

		// Client for MSID Lab vault (passwords)
		msidClient, err = confidential.New(
			microsoftAuthority,
			defaultClientId,
			cred,
			confidential.WithX5C(),
		)
		if err != nil {
			initErr = fmt.Errorf("failed to create MSID client: %w", err)
			return
		}

		// Client for MSAL Team vault (configs) - same client works for both
		msalClient = msidClient
	})
	return initErr
}

// GetSecret retrieves a secret from Key Vault by name
func GetSecret(ctx context.Context, vaultURL, secretName string) (string, error) {
	if err := initKeyVaultClients(); err != nil {
		return "", err
	}

	scope := vaultURL + "/.default"
	result, err := msalClient.AcquireTokenSilent(ctx, []string{scope})
	if err != nil {
		result, err = msalClient.AcquireTokenByCredential(ctx, []string{scope})
		if err != nil {
			return "", fmt.Errorf("failed to acquire Key Vault token: %w", err)
		}
	}

	// Use Azure SDK or direct REST call to get secret
	// For simplicity, showing the pattern - you'll need to add the actual Key Vault SDK call
	secretURL := fmt.Sprintf("%s/secrets/%s?api-version=7.4", vaultURL, secretName)

	req, err := http.NewRequestWithContext(ctx, "GET", secretURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+result.AccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("key Vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("key Vault returned status %d", resp.StatusCode)
	}

	var kvResp struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&kvResp); err != nil {
		return "", err
	}

	return kvResp.Value, nil
}

// GetUserConfig retrieves and caches user configuration from Key Vault
func GetUserConfig(secretName string) (*UserConfig, error) {
	cacheMu.RLock()
	if user, ok := userCache[secretName]; ok {
		cacheMu.RUnlock()
		return user, nil
	}
	cacheMu.RUnlock()

	ctx := context.Background()
	secretValue, err := GetSecret(ctx, msalTeamVault, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to get user config %s: %w", secretName, err)
	}

	var resp labResponse
	if err := json.Unmarshal([]byte(secretValue), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse user config: %w", err)
	}

	if resp.User == nil {
		return nil, fmt.Errorf("no user data in secret %s", secretName)
	}

	cacheMu.Lock()
	userCache[secretName] = resp.User
	cacheMu.Unlock()

	return resp.User, nil
}

// GetAppConfig retrieves and caches app configuration from Key Vault
func GetAppConfig(secretName string) (*AppConfig, error) {
	cacheMu.RLock()
	if app, ok := appCache[secretName]; ok {
		cacheMu.RUnlock()
		return app, nil
	}
	cacheMu.RUnlock()

	ctx := context.Background()
	secretValue, err := GetSecret(ctx, msalTeamVault, secretName)
	if err != nil {
		return nil, fmt.Errorf("failed to get app config %s: %w", secretName, err)
	}

	var resp labResponse
	if err := json.Unmarshal([]byte(secretValue), &resp); err != nil {
		return nil, fmt.Errorf("failed to parse app config: %w", err)
	}

	if resp.App == nil {
		return nil, fmt.Errorf("no app data in secret %s", secretName)
	}

	cacheMu.Lock()
	appCache[secretName] = resp.App
	cacheMu.Unlock()

	return resp.App, nil
}

// GetPassword retrieves the user's password from MSID Lab Key Vault
// This is a method on UserConfig for convenience, fetched lazily
func (u *UserConfig) GetPassword() (string, error) {
	if u.password != "" {
		return u.password, nil
	}

	if u.LabName == "" {
		return "", fmt.Errorf("user has no lab name for password lookup")
	}

	ctx := context.Background()
	password, err := GetSecret(ctx, msidLabVault, u.LabName)
	if err != nil {
		return "", fmt.Errorf("failed to get password for %s: %w", u.LabName, err)
	}

	u.password = password
	return password, nil
}

// getCertDataFromFile loads certificate and private key from a PEM file
func getCertDataFromFile(filePath string) ([]*x509.Certificate, crypto.PrivateKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading certificate file: %w", err)
	}

	cert, privateKey, err := confidential.CertFromPEM(data, "")
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	return cert, privateKey, nil
}

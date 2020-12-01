// Package storage holds all cached token information for MSAL. This storage can be
// augmented with third-party extensions to provide persistent storage. In that case,
// reads and writes in upper packages will call Serialize() to take the entire in-memory
// representation and write it to storage and Deserialize() to update the entire in-memory
// storage with what was in the persistent storage.  The persistent storage can only be
// accessed in this way because multiple MSAL clients written in multiple languages can
// access the same storage and must adhere to the same method that was defined
// previously.
package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// TODO(someone): This thing does not expire tokens and DeleteCachedRefreshToken
// is not implemented (or used anywhere).  Seems bad.

// Manager is an in-memory cache of access tokens, accounts and meta data. This data is
// updated on read/write calls. Deserialize() replaces all data stored here with whatever
// was given to it on each call.
type Manager struct {
	// TODO(jdoak): Going to refactor this (next PR).
	// All the maps here are going away.  The cacheSerializationContract holds all
	// this data, no need to copy it back, we can just access it directly.
	// Where cacheContract currently is, the value will change to an atomic.Value.
	// All reads will just yank the value, which will remove our need for sync.Mutex on
	// reads.  A write will still need to take a lock as to not loose data from two
	// different write calls serializing data. That will not block reads while the cache
	// gets updated. Should reduce contention.
	accessTokens  map[string]accessTokenCacheItem
	refreshTokens map[string]refreshTokenCacheItem
	idTokens      map[string]idTokenCacheItem
	accounts      map[string]msalbase.Account
	appMetadatas  map[string]appMetadata
	cacheContract *cacheSerializationContract

	mu sync.Mutex
}

// New is the constructor for Manager.
func New() *Manager {
	return &Manager{
		accessTokens:  map[string]accessTokenCacheItem{},
		refreshTokens: map[string]refreshTokenCacheItem{},
		idTokens:      map[string]idTokenCacheItem{},
		accounts:      map[string]msalbase.Account{},
		appMetadatas:  map[string]appMetadata{},
		cacheContract: createCacheSerializationContract(),
	}
}

func checkAlias(alias string, aliases []string) bool {
	for _, v := range aliases {
		if alias == v {
			return true
		}
	}
	return false
}

func isMatchingScopes(scopesOne []string, scopesTwo string) bool {
	newScopesTwo := msalbase.SplitScopes(scopesTwo)
	scopeCounter := 0
	for _, scope := range scopesOne {
		for _, otherScope := range newScopesTwo {
			if scope == otherScope {
				scopeCounter++
				continue
			}
		}
	}
	return scopeCounter == len(scopesOne)
}

func (m *Manager) TryReadCache(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (msalbase.StorageTokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes
	aadInstanceDiscovery := requests.CreateAadInstanceDiscovery(webRequestManager)
	metadata, err := aadInstanceDiscovery.GetMetadataEntry(ctx, authParameters.AuthorityInfo)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	accessToken, err := m.ReadAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	if err := accessToken.Validate(); err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	idToken, err := m.ReadIDToken(homeAccountID, metadata.Aliases, realm, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	appMetadata, err := m.ReadAppMetadata(metadata.Aliases, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	familyID := appMetadata.FamilyID

	refreshToken, err := m.ReadRefreshToken(homeAccountID, metadata.Aliases, familyID, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	account, err := m.ReadAccount(homeAccountID, metadata.Aliases, realm)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	return msalbase.CreateStorageTokenResponse(accessToken, refreshToken, idToken, account), nil
}

func (m *Manager) CacheTokenResponse(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error) {
	authParameters.HomeaccountID = tokenResponse.GetHomeAccountIDFromClientInfo()
	homeAccountID := authParameters.HomeaccountID
	environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	target := msalbase.ConcatenateScopes(tokenResponse.GrantedScopes)

	cachedAt := time.Now().Unix()

	var account msalbase.Account

	if tokenResponse.HasRefreshToken() {
		refreshToken := createRefreshTokenCacheItem(homeAccountID, environment, clientID, tokenResponse.RefreshToken, tokenResponse.FamilyID)
		if err := m.WriteRefreshToken(refreshToken); err != nil {
			return account, err
		}
	}

	if tokenResponse.HasAccessToken() {
		expiresOn := tokenResponse.ExpiresOn.Unix()
		extendedExpiresOn := tokenResponse.ExtExpiresOn.Unix()
		accessToken := createAccessTokenCacheItem(
			homeAccountID,
			environment,
			realm,
			clientID,
			cachedAt,
			expiresOn,
			extendedExpiresOn,
			target,
			tokenResponse.AccessToken,
		)

		// Since we have a valid access token, cache it before moving on.
		if err := accessToken.Validate(); err == nil {
			if err := m.WriteAccessToken(accessToken); err != nil {
				return account, err
			}
		}
	}

	idTokenJwt := tokenResponse.IDToken
	if !idTokenJwt.IsZero() {
		idToken := createIDTokenCacheItem(homeAccountID, environment, realm, clientID, idTokenJwt.RawToken)
		if err := m.WriteIDToken(idToken); err != nil {
			return msalbase.Account{}, err
		}

		localAccountID := idTokenJwt.GetLocalAccountID()
		authorityType := authParameters.AuthorityInfo.AuthorityType

		account = msalbase.NewAccount(
			homeAccountID,
			environment,
			realm,
			localAccountID,
			authorityType,
			idTokenJwt.PreferredUsername,
		)
		if err := m.WriteAccount(account); err != nil {
			return msalbase.Account{}, err
		}
	}

	appMetadata := createAppMetadata(tokenResponse.FamilyID, clientID, environment)

	if err := m.WriteAppMetadata(appMetadata); err != nil {
		return msalbase.Account{}, err
	}
	return account, nil
}

func (m *Manager) DeleteCachedRefreshToken(authParameters msalbase.AuthParametersInternal) error {
	return errors.New("Not implemented")
}

func (m *Manager) ReadAccessToken(homeID string, envAliases []string, realm, clientID string, scopes []string) (accessTokenCacheItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, at := range m.accessTokens {
		if at.HomeAccountID == homeID && at.Realm == realm && at.ClientID == clientID {
			if checkAlias(at.Environment, envAliases) {
				if isMatchingScopes(scopes, at.Scopes) {
					return at, nil
				}
			}
		}
	}
	return accessTokenCacheItem{}, fmt.Errorf("access token not found")
}

func (m *Manager) WriteAccessToken(accessToken accessTokenCacheItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := accessToken.CreateKey()
	m.accessTokens[key] = accessToken
	return nil
}

func (m *Manager) ReadRefreshToken(homeID string, envAliases []string, familyID, clientID string) (refreshTokenCacheItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	byFamily := func(rt refreshTokenCacheItem) bool {
		return matchFamilyRefreshToken(rt, homeID, envAliases)
	}
	byClient := func(rt refreshTokenCacheItem) bool {
		return matchClientIDRefreshToken(rt, homeID, envAliases, clientID)
	}

	var matchers []func(rt refreshTokenCacheItem) bool
	if familyID == "" {
		matchers = []func(rt refreshTokenCacheItem) bool{
			byClient, byFamily,
		}
	} else {
		matchers = []func(rt refreshTokenCacheItem) bool{
			byFamily, byClient,
		}
	}

	// TODO(jdoak): All the tests here pass, but Bogdan says this is
	// more complicated.  I'm opening an issue for this to have him
	// review the tests and suggest tests that would break this so
	// we can re-write against good tests. His comments as follow:
	// The algorithm is a bit more complex than this, I assume there are some tests covering everything. I would keep the order as is.
	// The algorithm is:
	// If application is NOT part of the family, search by client_ID
	// If app is part of the family or if we DO NOT KNOW if it's part of the family, search by family ID, then by client_id (we will know if an app is part of the family after the first token response).
	// https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/311fe8b16e7c293462806f397e189a6aa1159769/src/client/Microsoft.Identity.Client/Internal/Requests/Silent/CacheSilentStrategy.cs#L95
	for _, matcher := range matchers {
		for _, rt := range m.refreshTokens {
			if matcher(rt) {
				return rt, nil
			}
		}
	}

	return refreshTokenCacheItem{}, fmt.Errorf("refresh token not found")
}

func matchFamilyRefreshToken(rt refreshTokenCacheItem, homeID string, envAliases []string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.FamilyID != ""
}

func matchClientIDRefreshToken(rt refreshTokenCacheItem, homeID string, envAliases []string, clientID string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.ClientID == clientID
}

func (m *Manager) WriteRefreshToken(refreshToken refreshTokenCacheItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := refreshToken.CreateKey()
	m.refreshTokens[key] = refreshToken

	return nil
}

func (m *Manager) ReadIDToken(homeID string, envAliases []string, realm, clientID string) (idTokenCacheItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, idt := range m.idTokens {
		if idt.HomeAccountID == homeID && idt.Realm == realm && idt.ClientID == clientID {
			if checkAlias(idt.Environment, envAliases) {
				return idt, nil
			}
		}
	}
	return idTokenCacheItem{}, fmt.Errorf("token not found")
}

func (m *Manager) WriteIDToken(idToken idTokenCacheItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := idToken.CreateKey()
	m.idTokens[key] = idToken

	return nil
}

func (m *Manager) GetAllAccounts() ([]msalbase.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var accounts []msalbase.Account
	for _, v := range m.accounts {
		accounts = append(accounts, v)
	}

	return accounts, nil
}

func (m *Manager) ReadAccount(homeAccountID string, envAliases []string, realm string) (msalbase.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, acc := range m.accounts {
		if acc.HomeAccountID == homeAccountID && checkAlias(acc.Environment, envAliases) && acc.Realm == realm {
			return acc, nil
		}
	}
	return msalbase.Account{}, fmt.Errorf("account not found")
}

func (m *Manager) WriteAccount(account msalbase.Account) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := account.CreateKey()
	m.accounts[key] = account

	return nil
}

func (m *Manager) DeleteAccounts(homeID string, envAliases []string) error {
	keys := []string{}
	func() {
		m.mu.Lock()
		defer m.mu.Unlock()

		for key, acc := range m.accounts {
			if acc.HomeAccountID == homeID && checkAlias(acc.Environment, envAliases) {
				keys = append(keys, key)
			}
		}
	}()

	if len(keys) == 0 {
		return fmt.Errorf("can't find account for ID(%s)", homeID)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, key := range keys {
		delete(m.accounts, key)
	}

	return nil
}

func (m *Manager) ReadAppMetadata(envAliases []string, clientID string) (appMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, app := range m.appMetadatas {
		if checkAlias(app.Environment, envAliases) && app.ClientID == clientID {
			return app, nil
		}
	}
	return appMetadata{}, fmt.Errorf("not found")
}

func (m *Manager) WriteAppMetadata(appMetadata appMetadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := appMetadata.CreateKey()
	m.appMetadatas[key] = appMetadata

	return nil
}

func (m *Manager) Serialize() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO(jdoak): This looks weird, investigate later.
	m.cacheContract.AccessTokens = m.accessTokens
	m.cacheContract.RefreshTokens = m.refreshTokens
	m.cacheContract.IDTokens = m.idTokens
	m.cacheContract.Accounts = m.accounts
	m.cacheContract.AppMetadata = m.appMetadatas

	serializedCache, err := json.Marshal(m.cacheContract)
	if err != nil {
		return "", err
	}
	return string(serializedCache), nil // TODO(someone): while you can do the string conversion, this is costly. Investigate []byte
}

func (m *Manager) Deserialize(cacheData []byte) error {
	err := json.Unmarshal(cacheData, m.cacheContract)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.accessTokens = m.cacheContract.AccessTokens
	m.refreshTokens = m.cacheContract.RefreshTokens
	m.idTokens = m.cacheContract.IDTokens
	m.accounts = m.cacheContract.Accounts
	m.appMetadatas = m.cacheContract.AppMetadata

	return nil
}

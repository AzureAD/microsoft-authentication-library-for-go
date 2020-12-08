// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package storage holds all cached token information for MSAL. This storage can be
// augmented with third-party extensions to provide persistent storage. In that case,
// reads and writes in upper packages will call Serialize() to take the entire in-memory
// representation and write it to storage and Unmarshal() to update the entire in-memory
// storage with what was in the persistent storage.  The persistent storage can only be
// accessed in this way because multiple MSAL clients written in multiple languages can
// access the same storage and must adhere to the same method that was defined
// previously.
package storage

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/requests"
)

// TODO(someone): This thing does not expire tokens.

// Manager is an in-memory cache of access tokens, accounts and meta data. This data is
// updated on read/write calls. Unmarshal() replaces all data stored here with whatever
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
	contract atomic.Value // Stores a *Contract

	mu sync.Mutex
}

// New is the constructor for Manager.
func New() *Manager {
	m := &Manager{}
	m.contract.Store(NewContract())
	return m
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

// Read reads a storage token from the cache if it exists.
func (m *Manager) Read(ctx context.Context, authParameters msalbase.AuthParametersInternal, webRequestManager requests.WebRequestManager) (msalbase.StorageTokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes
	aadInstanceDiscovery := requests.CreateAadInstanceDiscovery(webRequestManager)
	metadata, err := aadInstanceDiscovery.GetMetadataEntry(ctx, authParameters.AuthorityInfo)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	accessToken, err := m.readAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	if err := accessToken.Validate(); err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	idToken, err := m.readIDToken(homeAccountID, metadata.Aliases, realm, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}

	AppMetaData, err := m.readAppMetaData(metadata.Aliases, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	familyID := AppMetaData.FamilyID

	refreshToken, err := m.readRefreshToken(homeAccountID, metadata.Aliases, familyID, clientID)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	account, err := m.readAccount(homeAccountID, metadata.Aliases, realm)
	if err != nil {
		return msalbase.StorageTokenResponse{}, err
	}
	return msalbase.CreateStorageTokenResponse(accessToken, refreshToken, idToken, account), nil
}

// Write writes a token response to the cache and returns the account information the token is stored with.
func (m *Manager) Write(authParameters msalbase.AuthParametersInternal, tokenResponse msalbase.TokenResponse) (msalbase.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	authParameters.HomeaccountID = tokenResponse.GetHomeAccountIDFromClientInfo()
	homeAccountID := authParameters.HomeaccountID
	environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	target := msalbase.ConcatenateScopes(tokenResponse.GrantedScopes)

	cachedAt := time.Now().Unix()

	var account msalbase.Account

	if tokenResponse.HasRefreshToken() {
		refreshToken := NewRefreshToken(homeAccountID, environment, clientID, tokenResponse.RefreshToken, tokenResponse.FamilyID)
		if err := m.writeRefreshToken(refreshToken); err != nil {
			return account, err
		}
	}

	if tokenResponse.HasAccessToken() {
		expiresOn := tokenResponse.ExpiresOn.Unix()
		extendedExpiresOn := tokenResponse.ExtExpiresOn.Unix()
		accessToken := NewAccessToken(
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
			if err := m.writeAccessToken(accessToken); err != nil {
				return account, err
			}
		}
	}

	idTokenJwt := tokenResponse.IDToken
	if !idTokenJwt.IsZero() {
		idToken := NewIDToken(homeAccountID, environment, realm, clientID, idTokenJwt.RawToken)
		if err := m.writeIDToken(idToken); err != nil {
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
		if err := m.writeAccount(account); err != nil {
			return msalbase.Account{}, err
		}
	}

	AppMetaData := NewAppMetaData(tokenResponse.FamilyID, clientID, environment)

	if err := m.writeAppMetaData(AppMetaData); err != nil {
		return msalbase.Account{}, err
	}
	return account, nil
}

// Contract returns the Contract for read operations.
func (m *Manager) Contract() *Contract {
	return m.contract.Load().(*Contract)
}

func (m *Manager) readAccessToken(homeID string, envAliases []string, realm, clientID string, scopes []string) (AccessToken, error) {
	cache := m.Contract()

	for _, at := range cache.AccessTokens {
		if at.HomeAccountID == homeID && at.Realm == realm && at.ClientID == clientID {
			if checkAlias(at.Environment, envAliases) {
				if isMatchingScopes(scopes, at.Scopes) {
					return at, nil
				}
			}
		}
	}
	return AccessToken{}, fmt.Errorf("access token not found")
}

func (m *Manager) writeAccessToken(accessToken AccessToken) error {
	key := accessToken.Key()

	cache := m.Contract().copy()
	cache.AccessTokens[key] = accessToken
	m.contract.Store(cache)
	return nil
}

func (m *Manager) readRefreshToken(homeID string, envAliases []string, familyID, clientID string) (RefreshToken, error) {
	byFamily := func(rt RefreshToken) bool {
		return matchFamilyRefreshToken(rt, homeID, envAliases)
	}
	byClient := func(rt RefreshToken) bool {
		return matchClientIDRefreshToken(rt, homeID, envAliases, clientID)
	}

	var matchers []func(rt RefreshToken) bool
	if familyID == "" {
		matchers = []func(rt RefreshToken) bool{
			byClient, byFamily,
		}
	} else {
		matchers = []func(rt RefreshToken) bool{
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
	cache := m.Contract()
	for _, matcher := range matchers {
		for _, rt := range cache.RefreshTokens {
			if matcher(rt) {
				return rt, nil
			}
		}
	}

	return RefreshToken{}, fmt.Errorf("refresh token not found")
}

func matchFamilyRefreshToken(rt RefreshToken, homeID string, envAliases []string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.FamilyID != ""
}

func matchClientIDRefreshToken(rt RefreshToken, homeID string, envAliases []string, clientID string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.ClientID == clientID
}

func (m *Manager) writeRefreshToken(refreshToken RefreshToken) error {
	key := refreshToken.Key()
	cache := m.Contract().copy()
	cache.RefreshTokens[key] = refreshToken
	m.contract.Store(cache)

	return nil
}

func (m *Manager) readIDToken(homeID string, envAliases []string, realm, clientID string) (IDToken, error) {
	cache := m.Contract()
	for _, idt := range cache.IDTokens {
		if idt.HomeAccountID == homeID && idt.Realm == realm && idt.ClientID == clientID {
			if checkAlias(idt.Environment, envAliases) {
				return idt, nil
			}
		}
	}
	return IDToken{}, fmt.Errorf("token not found")
}

func (m *Manager) writeIDToken(idToken IDToken) error {
	key := idToken.Key()
	cache := m.Contract().copy()
	cache.IDTokens[key] = idToken
	m.contract.Store(cache)

	return nil
}

func (m *Manager) GetAllAccounts() ([]msalbase.Account, error) {
	cache := m.Contract()

	var accounts []msalbase.Account
	for _, v := range cache.Accounts {
		accounts = append(accounts, v)
	}

	return accounts, nil
}

func (m *Manager) readAccount(homeAccountID string, envAliases []string, realm string) (msalbase.Account, error) {
	cache := m.Contract()

	// You might ask why, if cache.Accounts is a map, we would loop through all of these instead of using a key.
	// We only use a map because the storage contract shared between all language implementations says use a map.
	// We can't change that. The other is because the keys are made using a specific "env", but here we are allowing
	// a match in multiple envs (envAlias). That means we either need to hash each possible keyand do the lookup
	// or just statically check.  Since the design is to have a storage.Manager per user, the amount of keys stored
	// is really low (say 2).  Each hash is more expensive than the entire iteration.
	for _, acc := range cache.Accounts {
		if acc.HomeAccountID == homeAccountID && checkAlias(acc.Environment, envAliases) && acc.Realm == realm {
			return acc, nil
		}
	}
	return msalbase.Account{}, fmt.Errorf("account not found")
}

func (m *Manager) writeAccount(account msalbase.Account) error {
	key := account.Key()

	cache := m.Contract().copy()
	cache.Accounts[key] = account
	m.contract.Store(cache)

	return nil
}

func (m *Manager) deleteAccounts(homeID string, envAliases []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cache := m.Contract().copy()

	for key, acc := range cache.Accounts {
		if acc.HomeAccountID == homeID && checkAlias(acc.Environment, envAliases) {
			delete(cache.Accounts, key)
		}
	}

	m.contract.Store(cache)
	return nil
}

func (m *Manager) readAppMetaData(envAliases []string, clientID string) (AppMetaData, error) {
	cache := m.Contract()

	for _, app := range cache.AppMetaData {
		if checkAlias(app.Environment, envAliases) && app.ClientID == clientID {
			return app, nil
		}
	}
	return AppMetaData{}, fmt.Errorf("not found")
}

func (m *Manager) writeAppMetaData(AppMetaData AppMetaData) error {
	key := AppMetaData.Key()
	cache := m.Contract().copy()
	cache.AppMetaData[key] = AppMetaData
	m.contract.Store(cache)

	return nil
}

// update updates the internal cache object. This is for use in tests, other uses are not
// supported.
func (m *Manager) update(cache *Contract) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.contract.Store(cache)
}

// TODO(jdoak): Change this to return []byte, not string.

// Marshal implements cache.Marshaler.
func (m *Manager) Marshal() ([]byte, error) {
	b, err := json.Marshal(m.Contract())
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Unmarshal implements cache.Unmarshaler.
func (m *Manager) Unmarshal(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	contract := NewContract()

	err := json.Unmarshal(b, contract)
	if err != nil {
		return err
	}

	m.contract.Store(contract)

	return nil
}

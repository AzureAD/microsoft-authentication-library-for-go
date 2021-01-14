// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package storage holds all cached token information for MSAL. This storage can be
// augmented with third-party extensions to provide persistent storage. In that case,
// reads and writes in upper packages will call Marshal() to take the entire in-memory
// representation and write it to storage and Unmarshal() to update the entire in-memory
// storage with what was in the persistent storage.  The persistent storage can only be
// accessed in this way because multiple MSAL clients written in multiple languages can
// access the same storage and must adhere to the same method that was defined
// previously.
package storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/shared"
)

// aadInstanceDiscoveryer allows faking in tests.
// It is implemented in production by ops/authority.Client
type aadInstanceDiscoveryer interface {
	AADInstanceDiscovery(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryResponse, error)
}

// TokenResponse mimics a token response that was pulled from the cache.
type TokenResponse struct {
	RefreshToken accesstokens.RefreshToken
	IDToken      IDToken // *Credential
	AccessToken  AccessToken
	Account      shared.Account
}

// TODO(someone): This thing does not expire tokens.

// Manager is an in-memory cache of access tokens, accounts and meta data. This data is
// updated on read/write calls. Unmarshal() replaces all data stored here with whatever
// was given to it on each call.
type Manager struct {
	contract atomic.Value           // Stores a *Contract
	requests aadInstanceDiscoveryer // *oauth.Token

	mu sync.Mutex

	cacheMu  sync.Mutex
	aadCache map[string]authority.InstanceDiscoveryMetadata
}

// New is the constructor for Manager.
func New(requests *oauth.Client) *Manager {
	m := &Manager{requests: requests, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
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
	newScopesTwo := strings.Split(scopesTwo, scopeSeparator)
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
func (m *Manager) Read(ctx context.Context, authParameters authority.AuthParams) (TokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes

	metadata, err := m.getMetadataEntry(ctx, authParameters.AuthorityInfo)
	if err != nil {
		return TokenResponse{}, err
	}

	accessToken, err := m.readAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes)
	if err != nil {
		return TokenResponse{}, err
	}

	if err := accessToken.Validate(); err != nil {
		return TokenResponse{}, err
	}

	idToken, err := m.readIDToken(homeAccountID, metadata.Aliases, realm, clientID)
	if err != nil {
		return TokenResponse{}, err
	}

	AppMetaData, err := m.readAppMetaData(metadata.Aliases, clientID)
	if err != nil {
		return TokenResponse{}, err
	}
	familyID := AppMetaData.FamilyID

	refreshToken, err := m.readRefreshToken(homeAccountID, metadata.Aliases, familyID, clientID)
	if err != nil {
		return TokenResponse{}, err
	}
	account, err := m.readAccount(homeAccountID, metadata.Aliases, realm)
	if err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Account:      account,
	}, nil
}

const scopeSeparator = " "

// Write writes a token response to the cache and returns the account information the token is stored with.
func (m *Manager) Write(authParameters authority.AuthParams, tokenResponse accesstokens.TokenResponse) (shared.Account, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	authParameters.HomeaccountID = tokenResponse.ClientInfo.HomeAccountID()
	homeAccountID := authParameters.HomeaccountID
	environment := authParameters.AuthorityInfo.Host
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	target := strings.Join(tokenResponse.GrantedScopes.Slice, scopeSeparator)

	cachedAt := time.Now()

	var account shared.Account

	if len(tokenResponse.RefreshToken) > 0 {
		refreshToken := accesstokens.NewRefreshToken(homeAccountID, environment, clientID, tokenResponse.RefreshToken, tokenResponse.FamilyID)
		if err := m.writeRefreshToken(refreshToken); err != nil {
			return account, err
		}
	}

	if len(tokenResponse.AccessToken) > 0 {
		accessToken := NewAccessToken(
			homeAccountID,
			environment,
			realm,
			clientID,
			cachedAt,
			tokenResponse.ExpiresOn.T,
			tokenResponse.ExtExpiresOn.T,
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
			return shared.Account{}, err
		}

		localAccountID := idTokenJwt.LocalAccountID()
		authorityType := authParameters.AuthorityInfo.AuthorityType

		account = shared.NewAccount(
			homeAccountID,
			environment,
			realm,
			localAccountID,
			authorityType,
			idTokenJwt.PreferredUsername,
		)
		if err := m.writeAccount(account); err != nil {
			return shared.Account{}, err
		}
	}

	AppMetaData := NewAppMetaData(tokenResponse.FamilyID, clientID, environment)

	if err := m.writeAppMetaData(AppMetaData); err != nil {
		return shared.Account{}, err
	}
	return account, nil
}

// Contract returns the Contract for read operations.
func (m *Manager) Contract() *Contract {
	return m.contract.Load().(*Contract)
}

func (m *Manager) getMetadataEntry(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryMetadata, error) {
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	if metadata, ok := m.aadCache[authorityInfo.Host]; ok {
		return metadata, nil
	}
	metadata, err := m.aadMetadata(ctx, authorityInfo)
	if err != nil {
		return authority.InstanceDiscoveryMetadata{}, err
	}
	return metadata, nil
}

func (m *Manager) aadMetadata(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryMetadata, error) {
	discoveryResponse, err := m.requests.AADInstanceDiscovery(ctx, authorityInfo)
	if err != nil {
		return authority.InstanceDiscoveryMetadata{}, err
	}

	for _, metadataEntry := range discoveryResponse.Metadata {
		metadataEntry.TenantDiscoveryEndpoint = discoveryResponse.TenantDiscoveryEndpoint
		for _, aliasedAuthority := range metadataEntry.Aliases {
			m.aadCache[aliasedAuthority] = metadataEntry
		}
	}
	// TODO(msal): Don't understand this logic.  We query first this data, we enter all the data that
	// the server has.  If our host was not detailed by the server, we just insert it???
	// This is either broken or needs to be explained with a comment.
	if _, ok := m.aadCache[authorityInfo.Host]; !ok {
		m.aadCache[authorityInfo.Host] = authority.InstanceDiscoveryMetadata{
			PreferredNetwork: authorityInfo.Host,
			PreferredCache:   authorityInfo.Host,
		}
	}
	return m.aadCache[authorityInfo.Host], nil
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

func (m *Manager) readRefreshToken(homeID string, envAliases []string, familyID, clientID string) (accesstokens.RefreshToken, error) {
	byFamily := func(rt accesstokens.RefreshToken) bool {
		return matchFamilyRefreshToken(rt, homeID, envAliases)
	}
	byClient := func(rt accesstokens.RefreshToken) bool {
		return matchClientIDRefreshToken(rt, homeID, envAliases, clientID)
	}

	var matchers []func(rt accesstokens.RefreshToken) bool
	if familyID == "" {
		matchers = []func(rt accesstokens.RefreshToken) bool{
			byClient, byFamily,
		}
	} else {
		matchers = []func(rt accesstokens.RefreshToken) bool{
			byFamily, byClient,
		}
	}

	// TODO(keegan): All the tests here pass, but Bogdan says this is
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

	return accesstokens.RefreshToken{}, fmt.Errorf("refresh token not found")
}

func matchFamilyRefreshToken(rt accesstokens.RefreshToken, homeID string, envAliases []string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.FamilyID != ""
}

func matchClientIDRefreshToken(rt accesstokens.RefreshToken, homeID string, envAliases []string, clientID string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.ClientID == clientID
}

func (m *Manager) writeRefreshToken(refreshToken accesstokens.RefreshToken) error {
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

func (m *Manager) AllAccounts() ([]shared.Account, error) {
	cache := m.Contract()

	var accounts []shared.Account
	for _, v := range cache.Accounts {
		accounts = append(accounts, v)
	}

	return accounts, nil
}

func (m *Manager) readAccount(homeAccountID string, envAliases []string, realm string) (shared.Account, error) {
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
	return shared.Account{}, fmt.Errorf("account not found")
}

func (m *Manager) writeAccount(account shared.Account) error {
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

// Marshal implements cache.Marshaler.
func (m *Manager) Marshal() ([]byte, error) {
	return json.Marshal(m.Contract())
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

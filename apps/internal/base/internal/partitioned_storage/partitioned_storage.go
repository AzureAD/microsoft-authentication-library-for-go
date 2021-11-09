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
package partitioned_storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/internal/items"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/base/internal/storage"
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

// Manager is an in-memory cache of access tokens, accounts and meta data. This data is
// updated on read/write calls. Unmarshal() replaces all data stored here with whatever
// was given to it on each call.
type PartitionedManager struct {
	contract   *items.InMemoryContract
	contractMu sync.RWMutex
	requests   aadInstanceDiscoveryer // *oauth.Token

	aadCacheMu sync.RWMutex
	aadCache   map[string]authority.InstanceDiscoveryMetadata
}

// New is the constructor for Manager.
func New(requests *oauth.Client) *PartitionedManager {
	m := &PartitionedManager{requests: requests, aadCache: make(map[string]authority.InstanceDiscoveryMetadata)}
	m.contract = items.NewInMemoryContract()
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
			if strings.EqualFold(scope, otherScope) {
				scopeCounter++
				continue
			}
		}
	}
	return scopeCounter == len(scopesOne)
}

// Read reads a storage token from the cache if it exists.
func (m *PartitionedManager) Read(ctx context.Context, authParameters authority.AuthParams, account shared.Account, partitionKey string) (storage.TokenResponse, error) {
	homeAccountID := authParameters.HomeaccountID
	realm := authParameters.AuthorityInfo.Tenant
	clientID := authParameters.ClientID
	scopes := authParameters.Scopes

	metadata, err := m.getMetadataEntry(ctx, authParameters.AuthorityInfo)
	if err != nil {
		return storage.TokenResponse{}, err
	}

	accessToken, err := m.readApplicationAccessToken(homeAccountID, metadata.Aliases, realm, clientID, scopes, partitionKey)
	if err != nil {
		return storage.TokenResponse{}, err
	}

	if account.IsZero() {
		return storage.TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: accesstokens.RefreshToken{},
			IDToken:      items.IDToken{},
			Account:      shared.Account{},
		}, nil
	}
	idToken, err := m.readIDToken(metadata.Aliases, realm, clientID, partitionKey)
	if err != nil {
		return storage.TokenResponse{}, err
	}
	return storage.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: accesstokens.RefreshToken{},
		IDToken:      idToken,
		Account:      account,
	}, nil
}

const scopeSeparator = " "

// Write writes a token response to the cache and returns the account information the token is stored with.
func (m *PartitionedManager) Write(authParameters authority.AuthParams, tokenResponse accesstokens.TokenResponse, partitionKey string) (shared.Account, error) {
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
		if authParameters.AuthorizationType == authority.ATOnBehalfOf {
			refreshToken.UserAssertionHash = authParameters.AssertionHash()
		}
		if err := m.writeRefreshToken(refreshToken, partitionKey); err != nil {
			return account, err
		}
	}

	if len(tokenResponse.AccessToken) > 0 {
		accessToken := items.NewAccessToken(
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
		if authParameters.AuthorizationType == authority.ATOnBehalfOf {
			accessToken.UserAssertionHash = authParameters.AssertionHash() // get Hash method on this
		}

		// Since we have a valid access token, cache it before moving on.
		if err := accessToken.Validate(); err == nil {
			if err := m.writeAccessToken(accessToken, partitionKey); err != nil {
				return account, err
			}
		}
	}

	idTokenJwt := tokenResponse.IDToken
	if !idTokenJwt.IsZero() {
		idToken := items.NewIDToken(homeAccountID, environment, realm, clientID, idTokenJwt.RawToken)
		if authParameters.AuthorizationType == authority.ATOnBehalfOf {
			idToken.UserAssertionHash = authParameters.AssertionHash() // get Hash method on this
		}
		if err := m.writeIDToken(idToken, partitionKey); err != nil {
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
		if err := m.writeAccount(account, partitionKey); err != nil {
			return shared.Account{}, err
		}
	}

	AppMetaData := items.NewAppMetaData(tokenResponse.FamilyID, clientID, environment)

	if err := m.writeAppMetaData(AppMetaData); err != nil {
		return shared.Account{}, err
	}
	return account, nil
}

func (m *PartitionedManager) getMetadataEntry(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryMetadata, error) {
	md, err := m.aadMetadataFromCache(ctx, authorityInfo)
	if err != nil {
		// not in the cache, retrieve it
		md, err = m.aadMetadata(ctx, authorityInfo)
	}
	return md, err
}

func (m *PartitionedManager) aadMetadataFromCache(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryMetadata, error) {
	m.aadCacheMu.RLock()
	defer m.aadCacheMu.RUnlock()
	metadata, ok := m.aadCache[authorityInfo.Host]
	if ok {
		return metadata, nil
	}
	return metadata, errors.New("not found")
}

func (m *PartitionedManager) aadMetadata(ctx context.Context, authorityInfo authority.Info) (authority.InstanceDiscoveryMetadata, error) {
	m.aadCacheMu.Lock()
	defer m.aadCacheMu.Unlock()
	discoveryResponse, err := m.requests.AADInstanceDiscovery(ctx, authorityInfo)
	if err != nil {
		return authority.InstanceDiscoveryMetadata{}, err
	}

	for _, metadataEntry := range discoveryResponse.Metadata {
		for _, aliasedAuthority := range metadataEntry.Aliases {
			m.aadCache[aliasedAuthority] = metadataEntry
		}
	}
	if _, ok := m.aadCache[authorityInfo.Host]; !ok {
		m.aadCache[authorityInfo.Host] = authority.InstanceDiscoveryMetadata{
			PreferredNetwork: authorityInfo.Host,
			PreferredCache:   authorityInfo.Host,
		}
	}
	return m.aadCache[authorityInfo.Host], nil
}

func (m *PartitionedManager) readApplicationAccessToken(homeID string, envAliases []string, realm, clientID string, scopes []string, partitionKey string) (items.AccessToken, error) {
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()
	if accessTokens, ok := m.contract.AccessTokensPartition[partitionKey]; ok {
		// TODO: linear search (over a map no less) is slow for a large number (thousands) of tokens.
		// this shows up as the dominating node in a profile. for real-world scenarios this likely isn't
		// an issue, however if it does become a problem then we know where to look.
		for _, at := range accessTokens {
			if at.Realm == realm && at.ClientID == clientID {
				if checkAlias(at.Environment, envAliases) {
					if isMatchingScopes(scopes, at.Scopes) {
						return at, nil
					}
				}
			}
		}
	}
	return items.AccessToken{}, fmt.Errorf("access token not found")
}

func (m *PartitionedManager) writeAccessToken(accessToken items.AccessToken, partitionKey string) error {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	key := accessToken.Key()
	if m.contract.AccessTokensPartition[partitionKey] == nil {
		m.contract.AccessTokensPartition[partitionKey] = make(map[string]items.AccessToken)
	}
	m.contract.AccessTokensPartition[partitionKey][key] = accessToken
	return nil
}

func (m *PartitionedManager) readRefreshToken(homeID string, envAliases []string, familyID, clientID, partitionKey string) (accesstokens.RefreshToken, error) {
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
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()
	for _, matcher := range matchers {
		for _, rt := range m.contract.RefreshTokensPartition[partitionKey] {
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

func (m *PartitionedManager) writeRefreshToken(refreshToken accesstokens.RefreshToken, partitionKey string) error {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	key := refreshToken.Key()
	if m.contract.AccessTokensPartition[partitionKey] == nil {
		m.contract.RefreshTokensPartition[partitionKey] = make(map[string]accesstokens.RefreshToken)
	}
	m.contract.RefreshTokensPartition[partitionKey][key] = refreshToken
	return nil
}

func (m *PartitionedManager) readIDToken(envAliases []string, realm, clientID, partitionKey string) (items.IDToken, error) {
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()
	for _, idt := range m.contract.IDTokensPartition[partitionKey] {
		if idt.Realm == realm && idt.ClientID == clientID {
			if checkAlias(idt.Environment, envAliases) {
				return idt, nil
			}
		}
	}
	return items.IDToken{}, fmt.Errorf("token not found")
}

func (m *PartitionedManager) writeIDToken(idToken items.IDToken, partitionKey string) error {
	key := idToken.Key()
	// partitionKey := getKeyFromIDToken(idToken)
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	if m.contract.IDTokensPartition[partitionKey] == nil {
		m.contract.IDTokensPartition[partitionKey] = make(map[string]items.IDToken)
	}
	m.contract.IDTokensPartition[partitionKey][key] = idToken
	return nil
}

func (m *PartitionedManager) AllAccounts() []shared.Account {
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()

	var accounts []shared.Account
	// for _, v := range m.contract.Accounts {
	// 	accounts = append(accounts, v)
	// }

	return accounts
}

func (m *PartitionedManager) Account(homeAccountID string) shared.Account {
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()

	// for _, v := range m.contract.Accounts {
	// 	if v.HomeAccountID == homeAccountID {
	// 		return v
	// 	}
	// }

	return shared.Account{}
}

func (m *PartitionedManager) readAccount(homeAccountID string, envAliases []string, realm, partitionKey string) (shared.Account, error) {
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()

	// You might ask why, if cache.Accounts is a map, we would loop through all of these instead of using a key.
	// We only use a map because the storage contract shared between all language implementations says use a map.
	// We can't change that. The other is because the keys are made using a specific "env", but here we are allowing
	// a match in multiple envs (envAlias). That means we either need to hash each possible keyand do the lookup
	// or just statically check.  Since the design is to have a storage.Manager per user, the amount of keys stored
	// is really low (say 2).  Each hash is more expensive than the entire iteration.
	for _, acc := range m.contract.AccountsPartition[partitionKey] {
		if checkAlias(acc.Environment, envAliases) && acc.Realm == realm {
			return acc, nil
		}
	}
	return shared.Account{}, fmt.Errorf("account not found")
}

func (m *PartitionedManager) writeAccount(account shared.Account, partitionKey string) error {
	key := account.Key()
	// partitionKey := getKeyFromAccount(account)
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	if m.contract.AccountsPartition[partitionKey] == nil {
		m.contract.AccountsPartition[partitionKey] = make(map[string]shared.Account)
	}
	m.contract.AccountsPartition[partitionKey][key] = account
	return nil
}

func (m *PartitionedManager) readAppMetaData(envAliases []string, clientID string) (items.AppMetaData, error) {
	m.contractMu.RLock()
	defer m.contractMu.RUnlock()

	for _, app := range m.contract.AppMetaData {
		if checkAlias(app.Environment, envAliases) && app.ClientID == clientID {
			return app, nil
		}
	}
	return items.AppMetaData{}, fmt.Errorf("not found")
}

func (m *PartitionedManager) writeAppMetaData(AppMetaData items.AppMetaData) error {
	key := AppMetaData.Key()
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	m.contract.AppMetaData[key] = AppMetaData
	return nil
}

// RemoveAccount removes all the associated ATs, RTs and IDTs from the cache associated with this account.
func (m *PartitionedManager) RemoveAccount(account shared.Account, clientID string) {
	m.removeRefreshTokens(account.HomeAccountID, account.Environment, clientID)
	m.removeAccessTokens(account.HomeAccountID, account.Environment)
	m.removeIDTokens(account.HomeAccountID, account.Environment)
	m.removeAccounts(account.HomeAccountID, account.Environment)
}

func (m *PartitionedManager) removeRefreshTokens(homeID string, env string, clientID string) {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	// for key, rt := range m.contract.RefreshTokens {
	// 	// Check for RTs associated with the account.
	// 	if rt.HomeAccountID == homeID && rt.Environment == env {
	// 		// Do RT's app ownership check as a precaution, in case family apps
	// 		// and 3rd-party apps share same token cache, although they should not.
	// 		if rt.ClientID == clientID || rt.FamilyID != "" {
	// 			delete(m.contract.RefreshTokens, key)
	// 		}
	// 	}
	// }
}

func (m *PartitionedManager) removeAccessTokens(homeID string, env string) {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	// for key, at := range m.contract.AccessTokens {
	// 	// Remove AT's associated with the account
	// 	if at.HomeAccountID == homeID && at.Environment == env {
	// 		// # To avoid the complexity of locating sibling family app's AT, we skip AT's app ownership check.
	// 		// It means ATs for other apps will also be removed, it is OK because:
	// 		// non-family apps are not supposed to share token cache to begin with;
	// 		// Even if it happens, we keep other app's RT already, so SSO still works.
	// 		delete(m.contract.AccessTokens, key)
	// 	}
	// }
}

func (m *PartitionedManager) removeIDTokens(homeID string, env string) {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	// for key, idt := range m.contract.IDTokens {
	// 	// Remove ID tokens associated with the account.
	// 	if idt.HomeAccountID == homeID && idt.Environment == env {
	// 		delete(m.contract.IDTokens, key)
	// 	}
	// }
}

func (m *PartitionedManager) removeAccounts(homeID string, env string) {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()
	// for key, acc := range m.contract.Accounts {
	// 	// Remove the specified account.
	// 	if acc.HomeAccountID == homeID && acc.Environment == env {
	// 		delete(m.contract.Accounts, key)
	// 	}
	// }
}

// // update updates the internal cache object. This is for use in tests, other uses are not
// // supported.
// func (m *PartitionedManager) update(cache *items.InMemoryContract) {
// 	m.contractMu.Lock()
// 	defer m.contractMu.Unlock()
// 	m.contract = cache
// }

// Marshal implements cache.Marshaler.
func (m *PartitionedManager) Marshal() ([]byte, error) {
	return json.Marshal(m.contract)
}

// Unmarshal implements cache.Unmarshaler.
func (m *PartitionedManager) Unmarshal(b []byte) error {
	m.contractMu.Lock()
	defer m.contractMu.Unlock()

	contract := items.NewInMemoryContract()

	err := json.Unmarshal(b, contract)
	if err != nil {
		return err
	}

	m.contract = contract

	return nil
}

// func getKeyAccessToken(item items.AccessToken) string {
// 	if item.UserAssertionHash != "" {
// 		return item.UserAssertionHash
// 	}
// 	return item.HomeAccountID
// }

// func getKeyFromRefresh(item accesstokens.RefreshToken) string {
// 	if item.UserAssertionHash != "" {
// 		return item.UserAssertionHash
// 	}
// 	return item.HomeAccountID
// }

// func getKeyFromIDToken(item items.IDToken) string {
// 	return item.HomeAccountID
// }

// func getKeyFromAccount(item shared.Account) string {
// 	return item.HomeAccountID
// }

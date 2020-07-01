// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"github.com/patrickmn/go-cache"
)

var lock sync.RWMutex

type storageManager struct {
	cache         *cache.Cache
	accessTokens  map[string]*accessTokenCacheItem
	refreshTokens map[string]*refreshTokenCacheItem
	idTokens      map[string]*idTokenCacheItem
	accounts      map[string]*msalbase.Account
	appMetadatas  map[string]*AppMetadata
}

func CreateStorageManager() *storageManager {
	mgr := &storageManager{
		cache:         cache.New(cache.DefaultExpiration, time.Duration(10)),
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*AppMetadata),
	}
	return mgr
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
	sort.Strings(scopesOne)
	sort.Strings(newScopesTwo)
	return reflect.DeepEqual(scopesOne, newScopesTwo)
}

func (m *storageManager) ReadCredentials(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string,
	clientID string,
	familyID string,
	target string,
	types map[msalbase.CredentialType]bool) (*ReadCredentialsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) ReadAccessToken(
	homeAccountID string,
	envAliases []string,
	realm string,
	clientID string,
	scopes []string) *accessTokenCacheItem {
	lock.RLock()
	for _, at := range m.accessTokens {
		if at.HomeAccountID == homeAccountID &&
			checkAlias(at.Environment, envAliases) &&
			at.Realm == realm &&
			at.ClientID == clientID &&
			isMatchingScopes(scopes, at.Scopes) {
			lock.RUnlock()
			return at
		}
	}
	lock.RUnlock()
	return nil
}

func (m *storageManager) WriteAccessToken(accessToken *accessTokenCacheItem) error {
	lock.Lock()
	key := accessToken.CreateKey()
	m.accessTokens[key] = accessToken
	lock.Unlock()
	return nil
}

func (m *storageManager) WriteRefreshToken(refreshToken *refreshTokenCacheItem) error {
	lock.Lock()
	key := refreshToken.CreateKey()
	m.refreshTokens[key] = refreshToken
	lock.Unlock()
	return nil
}

func (m *storageManager) WriteIDToken(idToken *idTokenCacheItem) error {
	lock.Lock()
	key := idToken.CreateKey()
	m.idTokens[key] = idToken
	lock.Unlock()
	return nil
}

func (m *storageManager) DeleteCredentials(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string,
	clientID string,
	familyID string,
	target string,
	types map[msalbase.CredentialType]bool) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) ReadAllAccounts() []*msalbase.Account {
	lock.RLock()
	accounts := []*msalbase.Account{}
	for _, v := range m.accounts {
		accounts = append(accounts, v)
	}
	lock.RUnlock()
	return accounts
}

func (m *storageManager) ReadAccount(homeAccountID string, environment string, realm string) (*msalbase.Account, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) WriteAccount(account *msalbase.Account) error {
	lock.Lock()
	key := account.CreateKey()
	m.accounts[key] = account
	lock.Unlock()
	return nil
}

func (m *storageManager) DeleteAccount(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) ReadAppMetadata(environment string, clientID string) (*AppMetadata, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) WriteAppMetadata(appMetadata *AppMetadata) error {
	lock.Lock()
	key := appMetadata.CreateKey()
	m.appMetadatas[key] = appMetadata
	lock.Unlock()
	return nil
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

var lock sync.RWMutex

type defaultStorageManager struct {
	accessTokens  map[string]*accessTokenCacheItem
	refreshTokens map[string]*refreshTokenCacheItem
	idTokens      map[string]*idTokenCacheItem
	accounts      map[string]*msalbase.Account
	appMetadatas  map[string]*AppMetadata
	cacheContract *cacheSerializationContract
}

func CreateStorageManager() *defaultStorageManager {
	mgr := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*AppMetadata),
		cacheContract: createCacheSerializationContract(),
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

func (m *defaultStorageManager) ReadAccessToken(
	homeAccountID string,
	envAliases []string,
	realm string,
	clientID string,
	scopes []string) *accessTokenCacheItem {
	lock.RLock()
	defer lock.RUnlock()
	for _, at := range m.accessTokens {
		if msalbase.GetStringFromPointer(at.HomeAccountID) == homeAccountID &&
			checkAlias(msalbase.GetStringFromPointer(at.Environment), envAliases) &&
			msalbase.GetStringFromPointer(at.Realm) == realm &&
			msalbase.GetStringFromPointer(at.ClientID) == clientID &&
			isMatchingScopes(scopes, msalbase.GetStringFromPointer(at.Scopes)) {
			return at
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteAccessToken(accessToken *accessTokenCacheItem) error {
	lock.Lock()
	key := accessToken.CreateKey()
	m.accessTokens[key] = accessToken
	lock.Unlock()
	return nil
}

func (m *defaultStorageManager) ReadRefreshToken(
	homeAccountID string,
	envAliases []string,
	familyID string,
	clientID string,
) *refreshTokenCacheItem {

	lock.RLock()
	defer lock.RUnlock()
	if familyID != "" {
		for _, rt := range m.refreshTokens {
			if testClientIDRefreshToken(rt, homeAccountID, envAliases, clientID) {
				return rt
			}
		}
		for _, rt := range m.refreshTokens {
			if testFamilyRefreshToken(rt, homeAccountID, envAliases) {
				return rt
			}
		}
	} else {
		for _, rt := range m.refreshTokens {
			if testFamilyRefreshToken(rt, homeAccountID, envAliases) {
				return rt
			}
		}
		for _, rt := range m.refreshTokens {
			if testClientIDRefreshToken(rt, homeAccountID, envAliases, clientID) {
				return rt
			}
		}
	}
	return nil
}

func testFamilyRefreshToken(rt *refreshTokenCacheItem, homeAccountID string, envAliases []string) bool {
	return msalbase.GetStringFromPointer(rt.HomeAccountID) == homeAccountID &&
		checkAlias(msalbase.GetStringFromPointer(rt.Environment), envAliases) &&
		msalbase.GetStringFromPointer(rt.FamilyID) != ""
}

func testClientIDRefreshToken(rt *refreshTokenCacheItem, homeAccountID string, envAliases []string, clientID string) bool {
	return msalbase.GetStringFromPointer(rt.HomeAccountID) == homeAccountID &&
		checkAlias(msalbase.GetStringFromPointer(rt.Environment), envAliases) &&
		msalbase.GetStringFromPointer(rt.ClientID) == clientID
}

func (m *defaultStorageManager) WriteRefreshToken(refreshToken *refreshTokenCacheItem) error {
	lock.Lock()
	key := refreshToken.CreateKey()
	m.refreshTokens[key] = refreshToken
	lock.Unlock()
	return nil
}

func (m *defaultStorageManager) ReadIDToken(
	homeAccountID string,
	envAliases []string,
	realm string,
	clientID string,
) *idTokenCacheItem {
	lock.RLock()
	defer lock.RUnlock()
	for _, idt := range m.idTokens {
		if msalbase.GetStringFromPointer(idt.HomeAccountID) == homeAccountID &&
			checkAlias(msalbase.GetStringFromPointer(idt.Environment), envAliases) &&
			msalbase.GetStringFromPointer(idt.Realm) == realm &&
			msalbase.GetStringFromPointer(idt.ClientID) == clientID {
			return idt
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteIDToken(idToken *idTokenCacheItem) error {
	lock.Lock()
	key := idToken.CreateKey()
	m.idTokens[key] = idToken
	lock.Unlock()
	return nil
}

func (m *defaultStorageManager) ReadAllAccounts() []*msalbase.Account {
	lock.RLock()
	accounts := []*msalbase.Account{}
	for _, v := range m.accounts {
		accounts = append(accounts, v)
	}
	lock.RUnlock()
	return accounts
}

func (m *defaultStorageManager) ReadAccount(homeAccountID string, envAliases []string, realm string) *msalbase.Account {
	lock.RLock()
	defer lock.RUnlock()
	for _, acc := range m.accounts {
		if msalbase.GetStringFromPointer(acc.HomeAccountID) == homeAccountID &&
			checkAlias(msalbase.GetStringFromPointer(acc.Environment), envAliases) &&
			msalbase.GetStringFromPointer(acc.Realm) == realm {
			return acc
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteAccount(account *msalbase.Account) error {
	lock.Lock()
	key := account.CreateKey()
	m.accounts[key] = account
	lock.Unlock()
	return nil
}

func (m *defaultStorageManager) DeleteAccounts(
	homeAccountID string,
	envAliases []string) error {
	keys := []string{}
	lock.RLock()
	for key, acc := range m.accounts {
		if msalbase.GetStringFromPointer(acc.HomeAccountID) == homeAccountID &&
			checkAlias(msalbase.GetStringFromPointer(acc.Environment), envAliases) {
			keys = append(keys, key)
		}
	}
	lock.RUnlock()
	if len(keys) == 0 {
		return errors.New("Can't find account")
	}
	lock.Lock()
	for _, key := range keys {
		delete(m.accounts, key)
	}
	lock.Unlock()
	return nil
}

func (m *defaultStorageManager) ReadAppMetadata(envAliases []string, clientID string) *AppMetadata {
	lock.RLock()
	defer lock.RUnlock()
	for _, app := range m.appMetadatas {
		if checkAlias(msalbase.GetStringFromPointer(app.Environment), envAliases) &&
			msalbase.GetStringFromPointer(app.ClientID) == clientID {
			return app
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteAppMetadata(appMetadata *AppMetadata) error {
	lock.Lock()
	key := appMetadata.CreateKey()
	m.appMetadatas[key] = appMetadata
	lock.Unlock()
	return nil
}

func (m *defaultStorageManager) Serialize() (string, error) {
	lock.RLock()
	m.cacheContract.AccessTokens = m.accessTokens
	m.cacheContract.RefreshTokens = m.refreshTokens
	m.cacheContract.IDTokens = m.idTokens
	m.cacheContract.Accounts = m.accounts
	m.cacheContract.AppMetadata = m.appMetadatas
	lock.RUnlock()
	serializedCache, err := m.cacheContract.MarshalJSON()
	if err != nil {
		return "", err
	}
	return string(serializedCache), nil
}

func (m *defaultStorageManager) Deserialize(cacheData []byte) error {
	err := m.cacheContract.UnmarshalJSON(cacheData)
	if err != nil {
		return err
	}
	lock.Lock()
	m.accessTokens = m.cacheContract.AccessTokens
	m.refreshTokens = m.cacheContract.RefreshTokens
	m.idTokens = m.cacheContract.IDTokens
	m.accounts = m.cacheContract.Accounts
	m.appMetadatas = m.cacheContract.AppMetadata
	lock.Unlock()
	return nil
}

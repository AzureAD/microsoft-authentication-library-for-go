// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"fmt"
	"sync"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

// TODO(jdoak): Investigate this lock. It is strange to have a global lock.
// TODO(jdoak): Find out what our expected number of concurrent reads are and the expected number of tokens.
// RWMutex is only more performant in high reads with low writes. Also, if the number of tokens is low,
// we might be able to use atomic.Value with map copies to achieve lockless read/writes. If the token number
// is really low, we could replace this with slices.
var lock sync.RWMutex

type defaultStorageManager struct {
	accessTokens  map[string]*accessTokenCacheItem
	refreshTokens map[string]*refreshTokenCacheItem
	idTokens      map[string]*idTokenCacheItem
	accounts      map[string]*msalbase.Account
	appMetadatas  map[string]*appMetadata
	cacheContract *cacheSerializationContract
}

//CreateStorageManager creates an instance of defaultStorageManager as a StorageManager interface
func CreateStorageManager() StorageManager {
	mgr := &defaultStorageManager{
		accessTokens:  make(map[string]*accessTokenCacheItem),
		refreshTokens: make(map[string]*refreshTokenCacheItem),
		idTokens:      make(map[string]*idTokenCacheItem),
		accounts:      make(map[string]*msalbase.Account),
		appMetadatas:  make(map[string]*appMetadata),
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

func (m *defaultStorageManager) ReadAccessToken(homeID string, envAliases []string, realm, clientID string, scopes []string) *accessTokenCacheItem {
	lock.RLock()
	defer lock.RUnlock()
	for _, at := range m.accessTokens {
		if at.HomeAccountID == homeID && at.Realm == realm && at.ClientID == clientID {
			if checkAlias(at.Environment, envAliases) && isMatchingScopes(scopes, at.Scopes) {
				return at
			}
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteAccessToken(accessToken *accessTokenCacheItem) error {
	lock.Lock()
	defer lock.Unlock()

	key := accessToken.CreateKey()
	m.accessTokens[key] = accessToken
	return nil
}

func (m *defaultStorageManager) ReadRefreshToken(homeID string, envAliases []string, familyID, clientID string) *refreshTokenCacheItem {
	lock.RLock()
	defer lock.RUnlock()

	if familyID != "" {
		for _, rt := range m.refreshTokens {
			if matchFamilyRefreshToken(rt, homeID, envAliases) {
				return rt
			}
		}
		for _, rt := range m.refreshTokens {
			if matchClientIDRefreshToken(rt, homeID, envAliases, clientID) {
				return rt
			}
		}
	} else {
		for _, rt := range m.refreshTokens {
			if matchClientIDRefreshToken(rt, homeID, envAliases, clientID) {
				return rt
			}
		}

		for _, rt := range m.refreshTokens {
			if matchFamilyRefreshToken(rt, homeID, envAliases) {
				return rt
			}
		}
	}
	return nil
}

func matchFamilyRefreshToken(rt *refreshTokenCacheItem, homeID string, envAliases []string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.FamilyID != ""
}

func matchClientIDRefreshToken(rt *refreshTokenCacheItem, homeID string, envAliases []string, clientID string) bool {
	return rt.HomeAccountID == homeID && checkAlias(rt.Environment, envAliases) && rt.ClientID == clientID
}

func (m *defaultStorageManager) WriteRefreshToken(refreshToken *refreshTokenCacheItem) error {
	lock.Lock()
	defer lock.Unlock()

	key := refreshToken.CreateKey()
	m.refreshTokens[key] = refreshToken

	return nil
}

func (m *defaultStorageManager) ReadIDToken(homeID string, envAliases []string, realm, clientID string) *idTokenCacheItem {
	lock.RLock()
	defer lock.RUnlock()

	for _, idt := range m.idTokens {
		if idt.HomeAccountID == homeID && idt.Realm == realm && idt.ClientID == clientID {
			if checkAlias(idt.Environment, envAliases) {
				return idt
			}
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteIDToken(idToken *idTokenCacheItem) error {
	lock.Lock()
	defer lock.Unlock()

	key := idToken.CreateKey()
	m.idTokens[key] = idToken

	return nil
}

func (m *defaultStorageManager) ReadAllAccounts() []*msalbase.Account {
	lock.RLock()
	defer lock.RUnlock()

	accounts := []*msalbase.Account{}
	for _, v := range m.accounts {
		accounts = append(accounts, v)
	}

	return accounts
}

func (m *defaultStorageManager) ReadAccount(homeAccountID string, envAliases []string, realm string) *msalbase.Account {
	lock.RLock()
	defer lock.RUnlock()

	for _, acc := range m.accounts {
		if acc.HomeAccountID == homeAccountID && checkAlias(acc.Environment, envAliases) && acc.Realm == realm {
			return acc
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteAccount(account *msalbase.Account) error {
	lock.Lock()
	defer lock.Unlock()

	key := account.CreateKey()
	m.accounts[key] = account

	return nil
}

func (m *defaultStorageManager) DeleteAccounts(homeID string, envAliases []string) error {
	keys := []string{}
	func() {
		lock.RLock()
		defer lock.RUnlock()

		for key, acc := range m.accounts {
			if acc.HomeAccountID == homeID && checkAlias(acc.Environment, envAliases) {
				keys = append(keys, key)
			}
		}
	}()

	if len(keys) == 0 {
		return fmt.Errorf("can't find account for ID(%s)", homeID)
	}

	lock.Lock()
	defer lock.Unlock()

	for _, key := range keys {
		delete(m.accounts, key)
	}

	return nil
}

func (m *defaultStorageManager) ReadAppMetadata(envAliases []string, clientID string) *appMetadata {
	lock.RLock()
	defer lock.RUnlock()

	for _, app := range m.appMetadatas {
		if checkAlias(app.Environment, envAliases) && app.ClientID == clientID {
			return app
		}
	}
	return nil
}

func (m *defaultStorageManager) WriteAppMetadata(appMetadata *appMetadata) error {
	lock.Lock()
	defer lock.Unlock()

	key := appMetadata.CreateKey()
	m.appMetadatas[key] = appMetadata

	return nil
}

func (m *defaultStorageManager) Serialize() (string, error) {
	lock.RLock()
	defer lock.RUnlock()

	m.cacheContract.AccessTokens = m.accessTokens
	m.cacheContract.RefreshTokens = m.refreshTokens
	m.cacheContract.IDTokens = m.idTokens
	m.cacheContract.Accounts = m.accounts
	m.cacheContract.AppMetadata = m.appMetadatas

	serializedCache, err := m.cacheContract.MarshalJSON()
	if err != nil {
		return "", err
	}
	return string(serializedCache), nil // TODO(someone): while you can do the string conversion, this is costly. Investigate []byte
}

func (m *defaultStorageManager) Deserialize(cacheData []byte) error {
	err := m.cacheContract.UnmarshalJSON(cacheData)
	if err != nil {
		return err
	}

	lock.Lock()
	defer lock.Unlock()

	m.accessTokens = m.cacheContract.AccessTokens
	m.refreshTokens = m.cacheContract.RefreshTokens
	m.idTokens = m.cacheContract.IDTokens
	m.accounts = m.cacheContract.Accounts
	m.appMetadatas = m.cacheContract.AppMetadata

	return nil
}

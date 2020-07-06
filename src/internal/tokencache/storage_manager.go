// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"errors"
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

func (m *storageManager) ReadRefreshToken(
	homeAccountID string,
	envAliases []string,
	familyID string,
	clientID string,
) *refreshTokenCacheItem {
	lock.RLock()
	for _, rt := range m.refreshTokens {
		if rt.HomeAccountID == homeAccountID && checkAlias(rt.Environment, envAliases) {
			if familyID != "" && rt.FamilyID != "" && familyID == rt.FamilyID {
				lock.RUnlock()
				return rt
			}
			if clientID == rt.ClientID {
				lock.RUnlock()
				return rt
			}
		}
	}
	lock.RUnlock()
	return nil
}

func (m *storageManager) WriteRefreshToken(refreshToken *refreshTokenCacheItem) error {
	lock.Lock()
	key := refreshToken.CreateKey()
	m.refreshTokens[key] = refreshToken
	lock.Unlock()
	return nil
}

func (m *storageManager) ReadIDToken(
	homeAccountID string,
	envAliases []string,
	realm string,
	clientID string,
) *idTokenCacheItem {
	lock.RLock()
	for _, idt := range m.idTokens {
		if idt.HomeAccountID == homeAccountID &&
			checkAlias(idt.Environment, envAliases) &&
			idt.Realm == realm &&
			idt.ClientID == clientID {
			lock.RUnlock()
			return idt
		}
	}
	lock.RUnlock()
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

func (m *storageManager) ReadAccount(homeAccountID string, envAliases []string, realm string) *msalbase.Account {
	lock.RLock()
	for _, acc := range m.accounts {
		if acc.HomeAccountID == homeAccountID &&
			checkAlias(acc.Environment, envAliases) &&
			acc.Realm == realm {
			lock.RUnlock()
			return acc
		}
	}
	lock.RUnlock()
	return nil
}

func (m *storageManager) WriteAccount(account *msalbase.Account) error {
	lock.Lock()
	key := account.CreateKey()
	m.accounts[key] = account
	lock.Unlock()
	return nil
}

func (m *storageManager) DeleteAccount(
	homeAccountID string,
	environment string,
	realm string) error {
	lock.Lock()
	lock.Unlock()
	return errors.New("Can't find account")
}

func (m *storageManager) DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) ReadAppMetadata(envAliases []string, clientID string) *AppMetadata {
	lock.RLock()
	for _, app := range m.appMetadatas {
		if checkAlias(app.Environment, envAliases) && app.ClientID == clientID {
			lock.RUnlock()
			return app
		}
	}
	lock.RUnlock()
	return nil
}

func (m *storageManager) WriteAppMetadata(appMetadata *AppMetadata) error {
	lock.Lock()
	key := appMetadata.CreateKey()
	m.appMetadatas[key] = appMetadata
	lock.Unlock()
	return nil
}

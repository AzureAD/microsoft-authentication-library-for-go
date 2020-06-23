// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// +build windows

package tokencache

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type windowsStorageManager struct {
	cachekeyGenerator ICacheKeyGenerator
}

func CreateStorageManager(ckg ICacheKeyGenerator) IStorageManager {
	mgr := &windowsStorageManager{cachekeyGenerator: ckg}
	return mgr
}

func (m *windowsStorageManager) ReadCredentials(
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

func (m *windowsStorageManager) WriteCredentials(correlationID string, credentials []*msalbase.Credential) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) DeleteCredentials(
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

func (m *windowsStorageManager) ReadAllAccounts(correlationID string) (*ReadAccountsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) ReadAccount(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string) (*ReadAccountResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) WriteAccount(correlationID string, account *msalbase.Account) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) DeleteAccount(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) ReadAppMetadata(environment string, clientID string) (*AppMetadata, error) {
	return nil, errors.New("not implemented")
}

func (m *windowsStorageManager) WriteAppMetadata(appMetadata *AppMetadata) error {
	return errors.New("not implemented")
}

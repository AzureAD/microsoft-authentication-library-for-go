// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// +build windows

package tokencache

import (
	"errors"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type storageManager struct {
}

func CreateStorageManager() IStorageManager {
	mgr := &storageManager{}
	return mgr
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

func (m *storageManager) WriteCredentials(correlationID string, credentials []*msalbase.Credential) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
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

func (m *storageManager) ReadAllAccounts(correlationID string) (*ReadAccountsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) ReadAccount(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string) (*ReadAccountResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *storageManager) WriteAccount(correlationID string, account *msalbase.Account) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
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
	return errors.New("not implemented")
}

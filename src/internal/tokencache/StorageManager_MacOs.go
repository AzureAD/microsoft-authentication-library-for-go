// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// +build macos

package tokencache

import (
	"errors"

	"internal/msalbase"
)

type macosStorageManager struct {
}

func CreateStorageManager() IStorageManager {
	mgr := &macosStorageManager{}
	return mgr
}

func (m *macosStorageManager) ReadCredentials(
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

func (m *macosStorageManager) WriteCredentials(correlationID string, credentials []*msalbase.Credential) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) DeleteCredentials(
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

func (m *macosStorageManager) ReadAllAccounts(correlationID string) (*ReadAccountsResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) ReadAccount(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string) (*ReadAccountResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) WriteAccount(correlationID string, account *msalbase.Account) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) DeleteAccount(
	correlationID string,
	homeAccountID string,
	environment string,
	realm string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) ReadAppMetadata(environment string, clientID string) (*AppMetadata, error) {
	return nil, errors.New("not implemented")
}

func (m *macosStorageManager) WriteAppMetadata(appMetadata *AppMetadata) error {
	return errors.New("not implemented")
}

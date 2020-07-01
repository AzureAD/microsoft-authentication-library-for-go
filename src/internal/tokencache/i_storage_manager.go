// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type OperationStatusType int

const (
	OperationStatusTypeSuccess OperationStatusType = iota
	OperationStatusTypeFailure
	OperationStatusTypeRetriableError
)

type OperationStatus struct {
	StatusType        OperationStatusType
	Code              int
	StatusDescription string
	PlatformCode      int
	PlatformDomain    string
}

func CreateSuccessOperationStatus() *OperationStatus {
	status := &OperationStatus{StatusType: OperationStatusTypeSuccess}
	return status
}

type ReadCredentialsResponse struct {
	Credentials     []*msalbase.Credential
	OperationStatus *OperationStatus
}

type ReadAccountsResponse struct {
	Accounts        []*msalbase.Account
	OperationStatus *OperationStatus
}

type ReadAccountResponse struct {
	Account         *msalbase.Account
	OperationStatus *OperationStatus
}

type IStorageManager interface {
	ReadAccessToken(
		homeAccountID string,
		envAliases []string,
		realm string,
		clientID string,
		scopes []string) *accessTokenCacheItem

	WriteAccessToken(accessToken *accessTokenCacheItem) error

	WriteRefreshToken(refreshToken *refreshTokenCacheItem) error

	WriteIDToken(idToken *idTokenCacheItem) error

	DeleteCredentials(
		correlationId string,
		homeAccountId string,
		environment string,
		realm string,
		clientID string,
		familyID string,
		target string,
		types map[msalbase.CredentialType]bool) (*OperationStatus, error)

	ReadAllAccounts() []*msalbase.Account

	ReadAccount(homeAccountID string, environment string, realm string) (*msalbase.Account, error)

	WriteAccount(account *msalbase.Account) error

	DeleteAccount(
		correlationID string,
		homeAccountID string,
		environment string,
		realm string) (*OperationStatus, error)

	DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error)
	ReadAppMetadata(environment string, clientID string) (*AppMetadata, error)
	WriteAppMetadata(appMetadata *AppMetadata) error
}

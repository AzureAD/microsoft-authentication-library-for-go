package tokencache

import (
	"github.com/markzuber/msalgo/internal/msalbase"
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

type AppMetadata struct {
	Environment string
	ClientID    string
	FamilyID    string
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
	ReadCredentials(
		correlationID string,
		homeAccountID string,
		environment string,
		realm string,
		clientID string,
		familyID string,
		target string,
		types map[msalbase.CredentialType]bool) (*ReadCredentialsResponse, error)

	WriteCredentials(correlationID string, credentials []*msalbase.Credential) (*OperationStatus, error)

	DeleteCredentials(
		correlationId string,
		homeAccountId string,
		environment string,
		realm string,
		clientID string,
		familyID string,
		target string,
		types map[msalbase.CredentialType]bool) (*OperationStatus, error)

	ReadAllAccounts(correlationID string) (*ReadAccountsResponse, error)

	ReadAccount(
		correlationID string,
		homeAccountID string,
		environment string,
		realm string) (*ReadAccountResponse, error)

	WriteAccount(correlationID string, account *msalbase.Account) (*OperationStatus, error)

	DeleteAccount(
		correlationID string,
		homeAccountID string,
		environment string,
		realm string) (*OperationStatus, error)

	DeleteAccounts(correlationID string, homeAccountID string, environment string) (*OperationStatus, error)
	ReadAppMetadata(environment string, clientID string) (*AppMetadata, error)
	WriteAppMetadata(appMetadata *AppMetadata) error
}

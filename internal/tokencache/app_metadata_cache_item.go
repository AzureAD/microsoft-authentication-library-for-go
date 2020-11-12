// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type appMetadata struct {
	FamilyID    string `json:"family_id,omitempty"`
	ClientID    string `json:"client_id,omitempty"`
	Environment string `json:"environment,omitempty"`

	AdditionalFields map[string]interface{}
}

func createAppMetadata(familyID, clientID, environment string) appMetadata {
	return appMetadata{
		FamilyID:    familyID,
		ClientID:    clientID,
		Environment: environment,
	}
}

func (appMeta appMetadata) CreateKey() string {
	return strings.Join(
		[]string{msalbase.AppMetadataCacheID, appMeta.Environment, appMeta.ClientID},
		msalbase.CacheKeySeparator,
	)
}

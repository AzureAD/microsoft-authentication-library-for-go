// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type AppMetadata struct {
	FamilyID    string
	ClientID    string
	Environment string
}

func CreateAppMetadata(familyID string, clientID string, environment string) *AppMetadata {
	metadata := &AppMetadata{
		FamilyID:    familyID,
		ClientID:    clientID,
		Environment: environment,
	}
	return metadata
}

func (appMeta *AppMetadata) CreateKey() string {
	keyParts := []string{msalbase.AppMetadataCacheID, appMeta.Environment, appMeta.ClientID}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

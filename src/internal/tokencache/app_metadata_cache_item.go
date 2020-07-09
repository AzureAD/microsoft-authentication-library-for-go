// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type AppMetadata struct {
	FamilyID         string
	ClientID         string
	Environment      string
	additionalFields map[string]interface{}
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

func (appMeta *AppMetadata) populateFromJSONMap(j map[string]interface{}) error {
	appMeta.FamilyID = msalbase.ExtractExistingOrEmptyString(j, "family_id")
	appMeta.ClientID = msalbase.ExtractExistingOrEmptyString(j, "client_id")
	appMeta.Environment = msalbase.ExtractExistingOrEmptyString(j, "environment")
	appMeta.additionalFields = j
	return nil
}

func (appMeta *AppMetadata) convertToJSONMap() map[string]interface{} {
	jsonMap := appMeta.additionalFields
	jsonMap["family_id"] = appMeta.FamilyID
	jsonMap["client_id"] = appMeta.ClientID
	jsonMap["environment"] = appMeta.Environment
	return jsonMap
}

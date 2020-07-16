// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

type AppMetadata struct {
	FamilyID         *string `json:"family_id,omitempty"`
	ClientID         *string `json:"client_id,omitempty"`
	Environment      *string `json:"environment,omitempty"`
	additionalFields map[string]interface{}
}

func CreateAppMetadata(familyID string, clientID string, environment string) *AppMetadata {
	metadata := &AppMetadata{
		FamilyID:    &familyID,
		ClientID:    &clientID,
		Environment: &environment,
	}
	return metadata
}

func (appMeta *AppMetadata) CreateKey() string {
	keyParts := []string{msalbase.AppMetadataCacheID,
		msalbase.GetStringFromPointer(appMeta.Environment),
		msalbase.GetStringFromPointer(appMeta.ClientID),
	}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (appMeta *AppMetadata) populateFromJSONMap(j map[string]interface{}) error {
	appMeta.FamilyID = msalbase.ExtractStringPointerForCache(j, "family_id")
	appMeta.ClientID = msalbase.ExtractStringPointerForCache(j, "client_id")
	appMeta.Environment = msalbase.ExtractStringPointerForCache(j, "environment")
	appMeta.additionalFields = j
	return nil
}

func (appMeta *AppMetadata) convertToJSONMap() (map[string]interface{}, error) {
	appMap, err := json.Marshal(appMeta)
	if err != nil {
		return nil, err
	}
	newMap := make(map[string]interface{})
	err = json.Unmarshal(appMap, &newMap)
	if err != nil {
		return nil, err
	}
	for k, v := range appMeta.additionalFields {
		newMap[k] = v
	}
	return newMap, nil
}

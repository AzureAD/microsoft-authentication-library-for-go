// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type appMetadata struct {
	FamilyID         *string `json:"family_id,omitempty"`
	ClientID         *string `json:"client_id,omitempty"`
	Environment      *string `json:"environment,omitempty"`
	additionalFields map[string]interface{}
}

func createAppMetadata(familyID string, clientID string, environment string) *appMetadata {
	metadata := &appMetadata{
		FamilyID:    &familyID,
		ClientID:    &clientID,
		Environment: &environment,
	}
	return metadata
}

func (appMeta *appMetadata) CreateKey() string {
	keyParts := []string{msalbase.AppMetadataCacheID,
		msalbase.GetStringFromPointer(appMeta.Environment),
		msalbase.GetStringFromPointer(appMeta.ClientID),
	}
	return strings.Join(keyParts, msalbase.CacheKeySeparator)
}

func (appMeta *appMetadata) populateFromJSONMap(j map[string]interface{}) error {
	appMeta.FamilyID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONFamilyID)
	appMeta.ClientID = msalbase.ExtractStringPointerForCache(j, msalbase.JSONClientID)
	appMeta.Environment = msalbase.ExtractStringPointerForCache(j, msalbase.JSONEnvironment)
	appMeta.additionalFields = j
	return nil
}

func (appMeta *appMetadata) convertToJSONMap() (map[string]interface{}, error) {
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

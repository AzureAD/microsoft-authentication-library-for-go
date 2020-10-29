// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"encoding/json"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
)

type appMetadata struct {
	FamilyID         string `json:"family_id,omitempty"`
	ClientID         string `json:"client_id,omitempty"`
	Environment      string `json:"environment,omitempty"`
	additionalFields map[string]interface{}
}

func createAppMetadata(familyID, clientID, environment string) *appMetadata {
	return &appMetadata{
		FamilyID:    familyID,
		ClientID:    clientID,
		Environment: environment,
	}
}

func (appMeta *appMetadata) CreateKey() string {
	return strings.Join(
		[]string{msalbase.AppMetadataCacheID, appMeta.Environment, appMeta.ClientID},
		msalbase.CacheKeySeparator,
	)
}

func (appMeta *appMetadata) populateFromJSONMap(j map[string]interface{}) error {
	appMeta.FamilyID = msalbase.GetStringKey(j, msalbase.JSONFamilyID)
	appMeta.ClientID = msalbase.GetStringKey(j, msalbase.JSONClientID)
	appMeta.Environment = msalbase.GetStringKey(j, msalbase.JSONEnvironment)
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

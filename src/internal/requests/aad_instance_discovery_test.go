// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package requests

import (
	"reflect"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
)

func TestGetMetadataEntry(t *testing.T) {
	authInfo := &msalbase.AuthorityInfo{
		Host: "login.microsoft.com",
	}
	mockWRM := new(MockWebRequestManager)
	metEntry := &InstanceDiscoveryMetadata{
		Aliases: []string{"login.microsoft.com"},
	}
	instanceDisc := CreateAadInstanceDiscovery(mockWRM)
	instanceResp := &InstanceDiscoveryResponse{
		TenantDiscoveryEndpoint: "",
		Metadata:                []*InstanceDiscoveryMetadata{metEntry},
	}
	mockWRM.On("GetAadinstanceDiscoveryResponse", authInfo).Return(instanceResp, nil)
	actualMet, err := instanceDisc.GetMetadataEntry(authInfo)
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
	if !reflect.DeepEqual(actualMet, metEntry) {
		t.Errorf("Actual metadata entry %+v differs from expected metadata entry %+v", actualMet, metEntry)
	}
}

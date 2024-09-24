// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

const (
	// test Resources
	resource              = "https://demo.azure.com"
	resourceDefaultSuffix = "https://demo.azure.com/.default"

	token = "fakeToken"
)

type SuccessfulResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresOn   int64  `json:"expires_on"`
	ExpiresIn   int64  `json:"expires_in"`
	Resource    string `json:"resource"`
	TokenType   string `json:"token_type"`
	ClientID    string `json:"client_id"`
	ObjectID    string `json:"object_id"`
	ResourceID  string `json:"msi_res_id"`
}

type ErrorRespone struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

func getSuccessfulResponse(resource string, miType ID) ([]byte, error) {
	expiresOn := time.Now().Add(1 * time.Hour).Unix()
	var response SuccessfulResponse
	switch miType.(type) {
	case UserAssignedClientID:
		response = SuccessfulResponse{
			AccessToken: token,
			ExpiresOn:   expiresOn,
			Resource:    resource,
			TokenType:   "Bearer",
			ClientID:    "client_id",
		}
	case UserAssignedResourceID:
		response = SuccessfulResponse{
			AccessToken: token,
			ExpiresOn:   expiresOn,
			Resource:    resource,
			TokenType:   "Bearer",
			ResourceID:  "msi_res_id",
		}
	case UserAssignedObjectID:
		response = SuccessfulResponse{
			AccessToken: token,
			ExpiresOn:   expiresOn,
			Resource:    resource,
			TokenType:   "Bearer",
			ObjectID:    "object_id",
		}
	case systemAssignedValue:
		response = SuccessfulResponse{
			AccessToken: token,
			ExpiresOn:   expiresOn,
			Resource:    resource,
			TokenType:   "Bearer",
			ObjectID:    "object_id",
		}
	default:
		return nil, fmt.Errorf("unsupported type %T", miType)
	}
	jsonResponse, err := json.Marshal(response)
	return jsonResponse, err
}

func makeResponseWithErrorData(err string, desc string) ([]byte, error) {
	responseBody := ErrorRespone{
		Err:  err,
		Desc: desc,
	}
	jsonResponse, e := json.Marshal(responseBody)
	return jsonResponse, e
}

type resourceTestData struct {
	source   Source
	endpoint string
	resource string
	miType   ID
}

type errorTestData struct {
	code          int
	err           string
	desc          string
	correlationid string
}

func Test_SystemAssigned_Returns_AcquireToken_Failure(t *testing.T) {
	testCases := []errorTestData{
		{code: http.StatusNotFound,
			err:           "",
			desc:          "",
			correlationid: "121212"},
		{code: http.StatusNotImplemented,
			err:           "",
			desc:          "",
			correlationid: "121212"},
		{code: http.StatusServiceUnavailable,
			err:           "",
			desc:          "",
			correlationid: "121212"},
		{code: http.StatusBadRequest,
			err:           "invalid_request",
			desc:          "Identity not found",
			correlationid: "121212",
		},
	}

	for _, testCase := range testCases {
		t.Run(http.StatusText(testCase.code), func(t *testing.T) {
			fakeErrorClient := mock.Client{}
			responseBody, err := makeResponseWithErrorData(testCase.err, testCase.desc)
			if err != nil {
				t.Fatalf("error while forming json response : %s", err.Error())
			}
			fakeErrorClient.AppendResponse(mock.WithHTTPStatusCode(testCase.code),
				mock.WithBody(responseBody))
			client, err := New(SystemAssigned(), WithHTTPClient(&fakeErrorClient))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := client.AcquireToken(context.Background(), resource)
			if err == nil {
				t.Fatalf("should have encountered the error")
			}
			var callErr errors.CallErr
			if errors.As(err, &callErr) {
				if !strings.Contains(err.Error(), testCase.err) {
					t.Fatalf("expected message '%s' in error, got %q", testCase.err, callErr.Error())
				}
				if callErr.Resp.StatusCode != testCase.code {
					t.Fatalf("expected status code %d, got %d", testCase.code, callErr.Resp.StatusCode)
				}
			} else {
				t.Fatalf("expected error of type %T, got %T", callErr, err)
			}
			if resp.AccessToken != "" {
				t.Fatalf("accesstoken should be empty")
			}
		})
	}
}

func Test_SystemAssigned_Returns_Token_Success(t *testing.T) {
	testCases := []resourceTestData{
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resource, miType: SystemAssigned()},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: SystemAssigned()},
		{source: DefaultToIMDS, endpoint: imdsEndpoint, resource: resourceDefaultSuffix, miType: UserAssignedClientID("asd")},
	}
	for _, testCase := range testCases {

		t.Run(string(testCase.source), func(t *testing.T) {
			url := testCase.endpoint
			mockClient := mock.Client{}
			responseBody, err := getSuccessfulResponse(resource, testCase.miType)
			if err != nil {
				t.Fatalf("error while forming json response : %s", err.Error())
			}
			mockClient.AppendResponse(mock.WithHTTPStatusCode(http.StatusOK), mock.WithBody(responseBody))
			client, err := New(testCase.miType, WithHTTPClient(&mockClient))

			if err != nil {
				t.Fatal(err)
			}
			result, err := client.AcquireToken(context.Background(), testCase.resource)
			if !strings.HasPrefix(url, testCase.endpoint) {
				t.Fatalf("url request is not on %s got %s", testCase.endpoint, url)
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.AccessToken != token {
				t.Fatalf("wanted %q, got %q", token, result.AccessToken)
			}
		})
	}
}

func TestCreatingIMDSClient(t *testing.T) {
	tests := []struct {
		name    string
		id      ID
		wantErr bool
	}{
		{
			name: "System Assigned",
			id:   SystemAssigned(),
		},
		{
			name: "Client ID",
			id:   UserAssignedClientID("test-client-id"),
		},
		{
			name: "Resource ID",
			id:   UserAssignedResourceID("test-resource-id"),
		},
		{
			name: "Object ID",
			id:   UserAssignedObjectID("test-object-id"),
		},
		{
			name:    "Empty Client ID",
			id:      UserAssignedClientID(""),
			wantErr: true,
		},
		{
			name:    "Empty Resource ID",
			id:      UserAssignedResourceID(""),
			wantErr: true,
		},
		{
			name:    "Empty Object ID",
			id:      UserAssignedObjectID(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.id)
			if tt.wantErr {
				if err == nil {
					t.Fatal("client New() should return a error but did not.")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			} else {
				if client.miType.value() != tt.id.value() {
					t.Fatal("client New() did not assign a correct value to type.")
				}
			}
		})
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

// HTTP Helper
func httpRequest(url string, query map[string]string, accessToken string) ([]byte, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	q := request.URL.Query()
	for key, value := range query {
		q.Add(key, value)
	}
	request.URL.RawQuery = q.Encode()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Lab Interface

type labClient struct {
	labApplication *msal.ConfidentialClientApplication
}

// TODO : Add app object

type user struct {
	AppID            string `json:"appId"`
	ObjectID         string `json:"objectId"`
	UserType         string `json:"userType"`
	DisplayName      string `json:"displayName"`
	Licenses         string `json:"licences"`
	Upn              string `json:"upn"`
	Mfa              string `json:"mfa"`
	ProtectionPolicy string `json:"protectionPolicy"`
	HomeDomain       string `json:"homeDomain"`
	HomeUPN          string `json:"homeUPN"`
	B2cProvider      string `json:"b2cProvider"`
	LabName          string `json:"labName"`
	LastUpdatedBy    string `json:"lastUpdatedBy"`
	LastUpdatedDate  string `json:"lastUpdatedDate"`
	Password         string
}
type secret struct {
	Secret string `json:"value"`
}

func newLabClient() (*labClient, error) {
	secretS := os.Getenv("clientSecret")
	secret, err := msal.CreateClientCredentialFromSecret(secretS)
	if err != nil {
		return nil, err
	}
	options := msal.DefaultConfidentialClientApplicationOptions()
	clientID := os.Getenv("clientId")
	options.Authority = microsoftAuthority
	app, err := msal.NewConfidentialClientApplication(clientID, secret, &options)
	if err != nil {
		return nil, err
	}
	return &labClient{labApplication: app}, nil
}
func (l *labClient) getLabAccessToken() (string, error) {
	scopes := []string{msIDlabDefaultScope}
	result, err := l.labApplication.AcquireTokenSilent(context.Background(), scopes, nil)
	if err != nil {
		result, err = l.labApplication.AcquireTokenByClientCredential(context.Background(), scopes)
		if err != nil {
			return "", err
		}
	}
	return result.GetAccessToken(), nil
}

func (l *labClient) getUser(query map[string]string) (user, error) {
	accessToken, err := l.getLabAccessToken()
	if err != nil {
		return user{}, err
	}
	responseBody, err := httpRequest("https://msidlab.com/api/user", query, accessToken)
	if err != nil {
		return user{}, err
	}
	var users []user
	err = json.Unmarshal(responseBody, &users)
	if err != nil {
		return user{}, err
	}
	if len(users) == 0 {
		return user{}, errors.New("No user found")
	}
	user := users[0]
	user.Password, err = l.getSecret(map[string]string{"Secret": user.LabName})
	if err != nil {
		return user, err
	}
	return user, nil
}

func (l *labClient) getSecret(query map[string]string) (string, error) {
	accessToken, err := l.getLabAccessToken()
	if err != nil {
		return "", err
	}
	responseBody, err := httpRequest("https://msidlab.com/api/LabUserSecret", query, accessToken)
	if err != nil {
		return "", err
	}
	var secret secret
	err = json.Unmarshal(responseBody, &secret)
	if err != nil {
		return "", err
	}
	return secret.Secret, nil
}

// TODO: Add getApp() when needed

// TestConstants

// Scopes.
const (
	msIDlabDefaultScope = "https://msidlab.com/.default"
	graphDefaultScope   = "https://graph.windows.net/.default"
)

// MicrosoftAuthorityHost is the host authority for Microsoft.
const microsoftAuthorityHost = "https://login.microsoftonline.com/"

// Authority values.
const (
	organizationsAuthority = microsoftAuthorityHost + "organizations/"
	commonAuthority        = microsoftAuthorityHost + "common/"
	microsoftAuthority     = microsoftAuthorityHost + "microsoft.onmicrosoft.com"
	msIDlabTenantAuthority = microsoftAuthorityHost + "msidlab4.onmicrosoft.com"
)

// Tests

func getTestUser(lc *labClient, query map[string]string) user {
	testUser, err := lc.getUser(query)
	if err != nil {
		panic("Failed to get input user" + err.Error())
	}
	return testUser
}

func TestUsernamePassword(t *testing.T) {
	labClientInstance, err := newLabClient()
	if err != nil {
		panic("Failed to get a lab client" + err.Error())
	}
	tests := map[string]struct {
		user user
	}{
		"Managed": {user: getTestUser(labClientInstance, map[string]string{"usertype": "cloud"})},
		"ADFSv2":  {user: getTestUser(labClientInstance, map[string]string{"usertype": "federated", "federationProvider": "ADFSv2"})},
		"ADFSv3":  {user: getTestUser(labClientInstance, map[string]string{"usertype": "federated", "federationProvider": "ADFSv3"})},
		//"ADFSv4":  {user: getTestUser(labClientInstance, map[string]string{"usertype": "federated", "federationProvider": "ADFSv2"})},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			options := msal.DefaultPublicClientApplicationOptions()
			options.Authority = organizationsAuthority
			publicClientApp, err := msal.NewPublicClientApplication(tc.user.AppID, &options)
			if err != nil {
				panic(err)
			}
			result, err := publicClientApp.AcquireTokenByUsernamePassword(
				context.Background(),
				[]string{graphDefaultScope},
				tc.user.Upn,
				tc.user.Password,
			)
			if err != nil {
				t.Error(err)
			}
			if result.AccessToken == "" {
				t.Error("No access token found")
			}
			if result.Account.GetUsername() != tc.user.Upn {
				t.Errorf("Incorrect user account")
			}
		})
	}
}

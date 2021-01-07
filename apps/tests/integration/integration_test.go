// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

const (
	msIDlabDefaultScope = "https://msidlab.com/.default"
	graphDefaultScope   = "https://graph.windows.net/.default"
)

const microsoftAuthorityHost = "https://login.microsoftonline.com/"

const (
	organizationsAuthority = microsoftAuthorityHost + "organizations/"
	microsoftAuthority     = microsoftAuthorityHost + "microsoft.onmicrosoft.com"
	//msIDlabTenantAuthority = microsoftAuthorityHost + "msidlab4.onmicrosoft.com" - Will be needed in the furture
)

func httpRequest(url string, query url.Values, accessToken string) ([]byte, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build new http request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.URL.RawQuery = query.Encode()
	// TODO(msal): You should never use the DefaultClient. Also, we should use a
	// context.Context that limits how long we will wait.
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s) failed: %w", request.URL.String(), err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s): could not read body: %w", request.URL.String(), err)
	}
	return body, nil
}

type labClient struct {
	app confidential.Client
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
	Value string `json:"value"`
}

func newLabClient() (*labClient, error) {
	clientID := os.Getenv("clientId")
	secret := os.Getenv("clientSecret")

	cred, err := confidential.NewCredFromSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("could not create a cred from a secret: %w", err)
	}

	app, err := confidential.New("userID", clientID, cred, confidential.WithAuthority(microsoftAuthority))
	if err != nil {
		return nil, err
	}

	return &labClient{app: app}, nil
}
func (l *labClient) getLabAccessToken() (string, error) {
	scopes := []string{msIDlabDefaultScope}
	result, err := l.app.AcquireTokenSilent(context.Background(), scopes)
	if err != nil {
		result, err = l.app.AcquireTokenByCredential(context.Background(), scopes)
		if err != nil {
			return "", fmt.Errorf("AcquireTokenByCredential() error: %w", err)
		}
	}
	return result.GetAccessToken(), nil
}

func (l *labClient) getUser(query url.Values) (user, error) {
	accessToken, err := l.getLabAccessToken()
	if err != nil {
		return user{}, fmt.Errorf("problem getting lab access token: %w", err)
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
	user.Password, err = l.getSecret(url.Values{"Secret": []string{user.LabName}})
	if err != nil {
		return user, err
	}
	return user, nil
}

func (l *labClient) getSecret(query url.Values) (string, error) {
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
	return secret.Value, nil
}

// TODO: Add getApp() when needed

func getTestUser(desc string, lc *labClient, query url.Values) user {
	testUser, err := lc.getUser(query)
	if err != nil {
		panic(fmt.Sprintf("TestUsernamePassword(%s) setup: getTestUser(): Failed to get input user: %s", desc, err))
	}
	return testUser
}

func TestUsernamePassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	labClientInstance, err := newLabClient()
	if err != nil {
		panic("failed to get a lab client: " + err.Error())
	}

	tests := []struct {
		desc string
		vals url.Values
	}{
		{"Managed", url.Values{"usertype": []string{"cloud"}}},
		{"ADFSv2", url.Values{"usertype": []string{"federated"}, "federationProvider": []string{"ADFSv2"}}},
		{"ADFSv3", url.Values{"usertype": []string{"federated"}, "federationProvider": []string{"ADFSv3"}}},
		//{"ADFSv4", getTestUser(labClientInstance, url.Values{"usertype": []string{"federated"}, "federationProvider": []string{"ADFSv4"}})},
	}
	for _, test := range tests {
		user := getTestUser(test.desc, labClientInstance, test.vals)
		app, err := public.New(user.AppID, public.WithAuthority(organizationsAuthority))
		if err != nil {
			panic(errors.Verbose(err))
		}
		result, err := app.AcquireTokenByUsernamePassword(
			context.Background(),
			[]string{graphDefaultScope},
			user.Upn,
			user.Password,
		)
		if err != nil {
			t.Fatalf("TestUsernamePassword(%s): on AcquireTokenByUsernamePassword(): got err == %s, want err == nil", test.desc, errors.Verbose(err))
		}
		if result.AccessToken == "" {
			t.Fatalf("TestUsernamePassword(%s): got AccessToken == '', want AccessToken == non-empty string", test.desc)
		}
		if result.Account.PreferredUsername != user.Upn {
			t.Fatalf("TestUsernamePassword(%s): got Username == %s, want Username == %s", test.desc, result.Account.PreferredUsername, user.Upn)
		}
	}
}

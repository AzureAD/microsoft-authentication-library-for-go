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
	"time"

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

var httpClient = http.Client{}

func httpRequest(ctx context.Context, url string, query url.Values, accessToken string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build new http request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.URL.RawQuery = query.Encode()

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s) failed: %w", req.URL.String(), err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("http.Get(%s): could not read body: %w", req.URL.String(), err)
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

	app, err := confidential.New(clientID, cred, confidential.WithAuthority(microsoftAuthority))
	if err != nil {
		return nil, err
	}

	return &labClient{app: app}, nil
}
func (l *labClient) labAccessToken() (string, error) {
	scopes := []string{msIDlabDefaultScope}
	result, err := l.app.AcquireTokenSilent(context.Background(), scopes)
	if err != nil {
		result, err = l.app.AcquireTokenByCredential(context.Background(), scopes)
		if err != nil {
			return "", fmt.Errorf("AcquireTokenByCredential() error: %w", err)
		}
	}
	return result.AccessToken, nil
}

func (l *labClient) user(ctx context.Context, query url.Values) (user, error) {
	accessToken, err := l.labAccessToken()
	if err != nil {
		return user{}, fmt.Errorf("problem getting lab access token: %w", err)
	}

	responseBody, err := httpRequest(ctx, "https://msidlab.com/api/user", query, accessToken)
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
	user.Password, err = l.secret(ctx, url.Values{"Secret": []string{user.LabName}})
	if err != nil {
		return user, err
	}
	return user, nil
}

func (l *labClient) secret(ctx context.Context, query url.Values) (string, error) {
	accessToken, err := l.labAccessToken()
	if err != nil {
		return "", err
	}
	responseBody, err := httpRequest(ctx, "https://msidlab.com/api/LabUserSecret", query, accessToken)
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

func testUser(ctx context.Context, desc string, lc *labClient, query url.Values) user {
	testUser, err := lc.user(ctx, query)
	if err != nil {
		panic(fmt.Sprintf("TestUsernamePassword(%s) setup: testUser(): Failed to get input user: %s", desc, err))
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
		{"ADFSv4", url.Values{"usertype": []string{"federated"}, "federationProvider": []string{"ADFSv4"}}},
	}
	for _, test := range tests {
		ctx := context.Background()

		user := testUser(ctx, test.desc, labClientInstance, test.vals)
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
		if result.IDToken.IsZero() {
			t.Fatalf("TestUsernamePassword(%s): got IDToken == empty, want IDToken == non-empty struct", test.desc)
		}
		if result.Account.PreferredUsername != user.Upn {
			t.Fatalf("TestUsernamePassword(%s): got Username == %s, want Username == %s", test.desc, result.Account.PreferredUsername, user.Upn)
		}
	}
}

func TestConfidentialClientwithSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	clientID := os.Getenv("clientId")
	secret := os.Getenv("clientSecret")
	cred, err := confidential.NewCredFromSecret(secret)
	if err != nil {
		panic(errors.Verbose(err))
	}

	app, err := confidential.New(clientID, cred, confidential.WithAuthority(microsoftAuthority))
	if err != nil {
		panic(errors.Verbose(err))
	}
	scopes := []string{msIDlabDefaultScope}
	result, err := app.AcquireTokenByCredential(context.Background(), scopes)
	if err != nil {
		t.Fatalf("TestConfidentialClientwithSecret: on AcquireTokenByCredential(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if result.AccessToken == "" {
		t.Fatal("TestConfidentialClientwithSecret: on AcquireTokenByCredential(): got AccessToken == '', want AccessToken == non-empty string")
	}
	silentResult, err := app.AcquireTokenSilent(context.Background(), scopes)
	if err != nil {
		t.Fatalf("TestConfidentialClientwithSecret: on AcquireTokenSilent(): got err == %s, want err == nil", errors.Verbose(err))
	}
	if silentResult.AccessToken == "" {
		t.Fatal("TestConfidentialClientwithSecret: on AcquireTokenSilent(): got AccessToken == '', want AccessToken == non-empty string")
	}

}

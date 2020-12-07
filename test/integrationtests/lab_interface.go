package integrationtests

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/msal"
)

type labClient struct {
	labApplication *msal.ConfidentialClientApplication
}

/*
Commenting this until it is used in a test case
type app struct {
	AppType      string `json:"appType"`
	AppName      string `json:"appName"`
	AppID        string `json:"appId"`
	RedirectURI  string `json:"redirectUri"`
	Authority    string `json:"authority"`
	LabName      string `json:"labName"`
	ClientSecret string `json:"clientSecret"`
}
*/

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

func (l *labClient) getLabAccessToken() string {
	if l.labApplication == nil {
		secretS := os.Getenv("clientSecret")
		secret, err := msal.CreateClientCredentialFromSecret(secretS)
		if err != nil {
			log.Fatal(err)
		}
		options := msal.DefaultConfidentialClientApplicationOptions()
		clientID := os.Getenv("clientId")
		options.Authority = MicrosoftAuthority
		l.labApplication, err = msal.NewConfidentialClientApplication(clientID, secret, &options)
		if err != nil {
			log.Fatal(err)
		}

	}
	scopes := []string{"https://msidlab.com/.default"}
	result, err := l.labApplication.AcquireTokenByClientCredential(context.Background(), scopes)
	if err != nil {
		log.Fatal(err)
	}
	return result.GetAccessToken()
}

func (l *labClient) getUser(query map[string]string) user {
	response, err := sendRequestToLab("https://msidlab.com/api/user", query, l.getLabAccessToken())
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	var users []user
	err = json.Unmarshal(body, &users)
	if err != nil {
		log.Fatal(err)
	}
	user := users[0]
	user.Password = l.getSecret(map[string]string{"Secret": user.LabName})
	return user
}

func (l *labClient) getSecret(query map[string]string) string {
	response, err := sendRequestToLab("https://msidlab.com/api/LabUserSecret", query, l.getLabAccessToken())
	if err != nil {
		log.Fatal(err)
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	var secret secret
	err = json.Unmarshal(body, &secret)
	if err != nil {
		log.Fatal(err)
	}
	return secret.Secret
}

/*
Commenting this until we add tests that need this
func (l *labClient) getApp(query map[string]string) {
	// TODO: Abhidnya Patil
	// Implement this for other flows
}
*/

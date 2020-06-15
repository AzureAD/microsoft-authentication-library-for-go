// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src/msal"
	log "github.com/sirupsen/logrus"
)

//Config represents the config.json required to run the samples
type Config struct {
	ClientID            string   `json:"client_id"`
	Authority           string   `json:"authority"`
	Scopes              []string `json:"scopes"`
	Username            string   `json:"username"`
	Password            string   `json:"password"`
	RedirectURI         string   `json:"redirect_uri"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
}

//CreateConfig creates the Config struct from a json file
func CreateConfig(fileName string) *Config {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	data, err := ioutil.ReadAll(jsonFile)
	config := &Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

//createPCAParams is used to instantiate the parameters to create the Public Client Application
func createPCAParams(clientID string, authority string) *msalgo.PublicClientApplicationParameters {
	pcaParams := msalgo.CreatePublicClientApplicationParameters(clientID)
	pcaParams.SetAadAuthority(authority)
	return pcaParams
}

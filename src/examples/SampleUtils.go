// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	log "github.com/sirupsen/logrus"
)

type Config struct {
	ClientID  string   `json:"client_id"`
	Authority string   `json:"authority"`
	Scopes    []string `json:"scopes"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
}

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

func (c *Config) GetClientID() string {
	return c.ClientID
}

func (c *Config) GetAuthority() string {
	return c.Authority
}

func (c *Config) GetScopes() []string {
	return c.Scopes
}

func (c *Config) GetUsername() string {
	return c.Username
}

func (c *Config) GetPassword() string {
	return c.Password
}

//createPCAParams is used to instantiate the parameters to create the Public Client Application
func createPCAParams(clientID string, authority string) *msalgo.PublicClientApplicationParameters {
	pcaParams := msalgo.CreatePublicClientApplicationParameters(clientID)
	pcaParams.SetAadAuthority(authority)
	return pcaParams
}

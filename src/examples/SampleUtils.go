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

//Config represents the config.json required to run the samples
type Config struct {
	ClientID    string   `json:"client_id"`
	Authority   string   `json:"authority"`
	Scopes      []string `json:"scopes"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	RedirectURI string   `json:"redirect_uri"`
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

//GetClientID returns the Client ID of the config
func (c *Config) GetClientID() string {
	return c.ClientID
}

//GetAuthority returns the authority URI of the config
func (c *Config) GetAuthority() string {
	return c.Authority
}

//GetScopes returns all the scopes of the config
func (c *Config) GetScopes() []string {
	return c.Scopes
}

//GetUsername returns the username of the config
func (c *Config) GetUsername() string {
	return c.Username
}

//GetPassword returns the password of the config
func (c *Config) GetPassword() string {
	return c.Password
}

func (c *Config) GetRedirectURI() string {
	return c.RedirectURI
}

//createPCAParams is used to instantiate the parameters to create the Public Client Application
func createPCAParams(clientID string, authority string) *msalgo.PublicClientApplicationParameters {
	pcaParams := msalgo.CreatePublicClientApplicationParameters(clientID)
	pcaParams.SetAadAuthority(authority)
	return pcaParams
}

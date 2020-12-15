// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"encoding/json"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
)

// Config represents the config.json required to run the samples
type Config struct {
	ClientID            string   `json:"client_id"`
	Authority           string   `json:"authority"`
	Scopes              []string `json:"scopes"`
	Username            string   `json:"username"`
	Password            string   `json:"password"`
	RedirectURI         string   `json:"redirect_uri"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	State               string   `json:"state"`
	ClientSecret        string   `json:"client_secret"`
	Thumbprint          string   `json:"thumbprint"`
	KeyFile             string   `json:"pem_file"`
}

// CreateConfig creates the Config struct from a json file.
func CreateConfig(fileName string) *Config {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	data, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		log.Fatal(err)
	}

	config := &Config{}
	err = json.Unmarshal(data, config)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

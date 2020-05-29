// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	msalgo "github.com/AzureAD/microsoft-authentication-library-for-go/src"
	"github.com/shirou/gopsutil/host"
	"golang.org/x/crypto/ssh/terminal"
)

func createParams() *msalgo.PublicClientApplicationParameters {
	pcaParameters := msalgo.CreatePublicClientApplicationParameters("0615b6ca-88d4-4884-8729-b178178f7c27")
	pcaParameters.SetAadAuthority("https://login.microsoftonline.com/organizations")
	// pcaParameters.SetHttpClient()
	return pcaParameters
}

func acquireByDeviceCode() {
	pca, err := msalgo.CreatePublicClientApplication(createParams())
	if err != nil {
		log.Fatal(err)
	}

	log.Info("acquiring token by device code")
	deviceCodeParams := msalgo.CreateAcquireTokenDeviceCodeParameters([]string{"user.read"})
	result, err := pca.AcquireTokenByDeviceCode(deviceCodeParams)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("ACCESS TOKEN: " + result.GetAccessToken())
}

func readInput() string {
	reader := bufio.NewReader(os.Stdin)
	value, _ := reader.ReadString('\n')
	value = strings.TrimSpace(value)
	return value
}

func readMaskedInput() string {
	bytes, _ := terminal.ReadPassword(int(syscall.Stdin))
	value := string(bytes)
	value = strings.TrimSpace(value)
	return value
}

func acquireByUsernamePassword() {

	pca, err := msalgo.CreatePublicClientApplication(createParams())
	if err != nil {
		log.Fatal(err)
	}

	log.Info("acquiring token by username password")

	fmt.Println()
	fmt.Print("Enter username: ")
	userName := readInput()
	fmt.Print("Enter password: ")
	password := readMaskedInput()
	fmt.Println()
	fmt.Println()

	userNameParams := msalgo.CreateAcquireTokenUsernamePasswordParameters([]string{"user.read"}, userName, password)
	result, err := pca.AcquireTokenByUsernamePassword(userNameParams)
	if err != nil {
		log.Fatal(err)
	}
	log.Info("ACCESS TOKEN: " + result.GetAccessToken())
}

func main() {

	h, _ := host.Info()
	log.Infof("%#v", h)

	// set this to get function names in the logs:
	log.SetReportCaller(true)
	log.Info("creating pca")

	//acquireByDeviceCode()
	acquireByUsernamePassword()
}

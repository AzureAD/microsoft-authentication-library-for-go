// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"fmt"
	"strings"
	"time"
)

const (
	scopeSeparator = " "

	// CacheKeySeparator is used in creating the keys of the cache.
	CacheKeySeparator = "-"
)

// TODO(jdoak): This needs to move out of here.  Both apps/public and apps/confidential return
// this. Or at the least, we need to type alias this up there.

type Account struct {
	HomeAccountID     string `json:"home_account_id,omitempty"`
	Environment       string `json:"environment,omitempty"`
	Realm             string `json:"realm,omitempty"`
	LocalAccountID    string `json:"local_account_id,omitempty"`
	AuthorityType     string `json:"authority_type,omitempty"`
	PreferredUsername string `json:"username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Name              string `json:"name,omitempty"`
	AlternativeID     string `json:"alternative_account_id,omitempty"`
	RawClientInfo     string `json:"client_info,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewAccount creates an account.
func NewAccount(homeAccountID, env, realm, localAccountID, authorityType, username string) Account {
	return Account{
		HomeAccountID:     homeAccountID,
		Environment:       env,
		Realm:             realm,
		LocalAccountID:    localAccountID,
		AuthorityType:     authorityType,
		PreferredUsername: username,
	}
}

// Key creates the key for storing accounts in the cache.
func (acc Account) Key() string {
	return strings.Join([]string{acc.HomeAccountID, acc.Environment, acc.Realm}, CacheKeySeparator)
}

// GetUsername returns the username of an account.
func (acc Account) GetUsername() string {
	return acc.PreferredUsername
}

// GetHomeAccountID returns the home account ID of an account.
func (acc Account) GetHomeAccountID() string {
	return acc.HomeAccountID
}

// GetEnvironment returns the environment of an account.
func (acc Account) GetEnvironment() string {
	return acc.Environment
}

// DeviceCodeResult stores the response from the STS device code endpoint.
// TODO(jdoak): Make these attributes public, maybe remove .String().
type DeviceCodeResult struct {
	// UserCode is the code the user needs to provide when authentication at the verification URI.
	UserCode string
	// DeviceCode is the code used in the access token request.
	DeviceCode string
	// VerificationURL is the the URL where user can authenticate.
	VerificationURL string
	// ExpiresOn is the expiration time of device code in seconds.
	ExpiresOn time.Time
	// Interval is the interval at which the STS should be polled at.
	Interval int
	// Message is the message which should be displayed to the user.
	Message string
	// ClientID is the UUID issued by the authorization server for your application.
	ClientID string
	// Scopes is the OpenID scopes used to request access a protected API.
	Scopes []string
}

// NewDeviceCodeResult creates a DeviceCodeResult instance.
func NewDeviceCodeResult(userCode, deviceCode, verificationURL string, expiresOn time.Time, interval int, message, clientID string, scopes []string) DeviceCodeResult {
	return DeviceCodeResult{userCode, deviceCode, verificationURL, expiresOn, interval, message, clientID, scopes}
}

func (dcr DeviceCodeResult) String() string {
	return fmt.Sprintf("UserCode: (%v)\nDeviceCode: (%v)\nURL: (%v)\nMessage: (%v)\n", dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, dcr.Message)

}

// RefreshToken is the JSON representation of a MSAL refresh token for encoding to storage.
type RefreshToken struct {
	HomeAccountID  string `json:"home_account_id,omitempty"`
	Environment    string `json:"environment,omitempty"`
	CredentialType string `json:"credential_type,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
	FamilyID       string `json:"family_id,omitempty"`
	Secret         string `json:"secret,omitempty"`
	Realm          string `json:"realm,omitempty"`
	Target         string `json:"target,omitempty"`

	AdditionalFields map[string]interface{}
}

// NewRefreshToken is the constructor for RefreshToken.
func NewRefreshToken(homeID, env, clientID, refreshToken, familyID string) RefreshToken {
	return RefreshToken{
		HomeAccountID:  homeID,
		Environment:    env,
		CredentialType: "RefreshToken",
		ClientID:       clientID,
		FamilyID:       familyID,
		Secret:         refreshToken,
	}
}

// Key outputs the key that can be used to uniquely look up this entry in a map.
func (rt RefreshToken) Key() string {
	var fourth = rt.FamilyID
	if fourth == "" {
		fourth = rt.ClientID
	}

	return strings.Join(
		[]string{rt.HomeAccountID, rt.Environment, rt.CredentialType, fourth},
		CacheKeySeparator,
	)
}

func (rt RefreshToken) GetSecret() string {
	return rt.Secret
}

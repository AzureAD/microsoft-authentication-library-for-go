// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package broker

import (
	"errors"
	"strings"
	"time"
	"unsafe"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal"
	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/broker"
	"golang.org/x/sys/windows"
)

// result of an msalruntime async operation
type result struct {
	ar  internal.AuthResult
	err error
}

// Account represents an msalruntime Account
type Account struct {
	handle uintptr
}

func (a Account) ClientInfo() (string, error) {
	return callStringMethod(getClientInfo, a.handle)
}

func (a Account) Environment() (string, error) {
	return callStringMethod(getEnvironment, a.handle)
}

func (a Account) FamilyName() (string, error) {
	return callStringMethod(getFamilyName, a.handle)
}

func (a Account) GivenName() (string, error) {
	return callStringMethod(getGivenName, a.handle)
}

func (a Account) HomeAccountID() (string, error) {
	return callStringMethod(getHomeAccountID, a.handle)
}

func (a Account) LocalAccountID() (string, error) {
	return callStringMethod(getLocalAccountID, a.handle)
}

func (a Account) MiddleName() (string, error) {
	return callStringMethod(getMiddleName, a.handle)
}

func (a Account) Name() (string, error) {
	return callStringMethod(getDisplayName, a.handle)
}

func (a Account) PreferredUsername() (string, error) {
	return callStringMethod(getUserName, a.handle)
}

func (a Account) Realm() (string, error) {
	return callStringMethod(getRealm, a.handle)
}

func (a Account) Release() error {
	errHandle, _, _ := releaseAccount.Call(a.handle)
	return convertError(errHandle)
}

// AuthParameters represents an msalruntime AuthParameters
type AuthParameters struct {
	handle uintptr
}

// newAuthParameters converts MSAL Go AuthParams to msalruntime AuthParameters
func newAuthParameters(ap broker.AuthParams) (AuthParameters, error) {
	if len(ap.Scopes) == 0 {
		return AuthParameters{}, errors.New("authentication requires at least one scope")
	}
	p := AuthParameters{}
	clientID, err := windows.UTF16PtrFromString(ap.ClientID)
	if err != nil {
		return p, err
	}
	authority, err := windows.UTF16PtrFromString(ap.Authority)
	if err != nil {
		return p, err
	}
	errHandle, _, _ := createAuthParameters.Call(
		uintptr(unsafe.Pointer(clientID)),
		uintptr(unsafe.Pointer(authority)),
		uintptr(unsafe.Pointer(&p.handle)),
	)
	if errHandle != 0 {
		return p, convertError(errHandle)
	}
	if err != nil {
		return p, err
	}
	if ap.Claims != "" {
		err = p.SetDecodedClaims(ap.Claims)
		if err != nil {
			return p, err
		}
	}
	if ap.RedirectURI != "" {
		err = p.SetRedirectURI(ap.RedirectURI)
		if err != nil {
			return p, err
		}
	}
	err = p.SetRequestedScopes(ap.Scopes)
	return p, err
}

func (ap AuthParameters) Release() error {
	errHandle, _, _ := releaseAuthParameters.Call(ap.handle)
	return convertError(errHandle)
}

func (ap AuthParameters) SetAdditionalParameter(key, value string) error {
	errHandle, _, _ := setAddtionalParameter.Call(
		ap.handle,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(key))),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(value))),
	)
	return convertError(errHandle)
}

func (ap AuthParameters) SetDecodedClaims(claims string) error {
	errHandle, _, _ := setDecodedClaims.Call(
		ap.handle,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(claims))),
	)
	return convertError(errHandle)
}

func (ap AuthParameters) SetRedirectURI(uri string) error {
	errHandle, _, _ := setRedirectURI.Call(
		ap.handle,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(uri))),
	)
	return convertError(errHandle)
}

func (ap AuthParameters) SetRequestedScopes(scopes []string) error {
	s, err := windows.UTF16PtrFromString(strings.Join(scopes, " "))
	if err != nil {
		return err
	}
	errHandle, _, _ := setRequestedScopes.Call(ap.handle, uintptr(unsafe.Pointer(s)))
	return convertError(errHandle)
}

// AuthResult represents an msalruntime AuthResult
type AuthResult struct {
	handle uintptr
}

func (ar AuthResult) AccessToken() (string, error) {
	return callStringMethod(getAccessToken, ar.handle)
}

func (ar AuthResult) Account() (Account, error) {
	account := Account{}
	errHandle, _, _ := getAccount.Call(ar.handle, uintptr(unsafe.Pointer(&account.handle)))
	return account, convertError(errHandle)
}

// Convert an msalruntime AuthResult to an MSAL Go AuthResult
func (ar AuthResult) Convert() (internal.AuthResult, error) {
	tk, err := ar.AccessToken()
	if err != nil {
		return internal.AuthResult{}, err
	}

	rawIDT, err := ar.IDToken()
	if err != nil {
		return internal.AuthResult{}, err
	}
	idt := public.IDToken{}
	err = idt.UnmarshalJSON([]byte(rawIDT))
	if err != nil {
		return internal.AuthResult{}, err
	}

	mrAccount, err := ar.Account()
	if err != nil {
		return internal.AuthResult{}, err
	}
	defer mrAccount.Release()

	a := public.Account{}
	a.RawClientInfo, err = mrAccount.ClientInfo()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.Environment, err = mrAccount.Environment()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.FamilyName, err = mrAccount.FamilyName()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.GivenName, err = mrAccount.GivenName()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.HomeAccountID, err = mrAccount.HomeAccountID()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.LocalAccountID, err = mrAccount.LocalAccountID()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.MiddleName, err = mrAccount.MiddleName()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.Name, err = mrAccount.Name()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.PreferredUsername, err = mrAccount.PreferredUsername()
	if err != nil {
		return internal.AuthResult{}, err
	}
	a.Realm, err = mrAccount.Realm()
	if err != nil {
		return internal.AuthResult{}, err
	}

	granted, err := ar.GrantedScopes()
	if err != nil {
		return internal.AuthResult{}, err
	}

	exp, err := ar.ExpiresOn()
	if err != nil {
		return internal.AuthResult{}, err
	}

	return internal.AuthResult{
		AccessToken:   tk,
		Account:       a,
		ExpiresOn:     time.Unix(int64(exp), 0),
		GrantedScopes: strings.Split(granted, " "),
		IDToken:       idt,
	}, nil
}

func (ar AuthResult) Error() error {
	var authErrHandle uintptr
	var err error
	errHandle, _, _ := getError.Call(ar.handle, uintptr(unsafe.Pointer(&authErrHandle)))
	if errHandle != 0 {
		// can't get authentication error details because getError itself failed
		err = convertError(errHandle)
	} else if authErrHandle != 0 {
		err = convertError(authErrHandle)
	}
	return err
}

func (ar AuthResult) ExpiresOn() (uint, error) {
	return callUintMethod(getExpiresOn, ar.handle)
}

func (ar AuthResult) GrantedScopes() (string, error) {
	return callStringMethod(getGrantedScopes, ar.handle)
}

func (ar AuthResult) IDToken() (string, error) {
	return callStringMethod(getRawIdToken, ar.handle)
}

func (ar AuthResult) Release() error {
	errHandle, _, _ := releaseAuthResult.Call(ar.handle)
	return convertError(errHandle)
}

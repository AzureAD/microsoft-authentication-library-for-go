// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type StorageTokenResponse struct {
	accessToken  *Credential
	refreshToken *Credential
	idToken      *Credential
	account      *Account
}

func CreateStorageTokenResponse(accessToken *Credential, refreshToken *Credential, idToken *Credential, account *Account) *StorageTokenResponse {
	tr := &StorageTokenResponse{accessToken, refreshToken, idToken, account}
	return tr
}

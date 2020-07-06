// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type StorageTokenResponse struct {
	accessToken  IAccessToken
	RefreshToken Credential
	idToken      Credential
	account      *Account
}

func CreateStorageTokenResponse(accessToken IAccessToken, refreshToken Credential, idToken Credential, account *Account) *StorageTokenResponse {
	tr := &StorageTokenResponse{accessToken, refreshToken, idToken, account}
	return tr
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

//StorageTokenResponse mimics a token response that was pulled from the cache
type StorageTokenResponse struct {
	accessToken  IAccessToken
	RefreshToken Credential
	idToken      Credential
	account      *Account
}

//CreateStorageTokenResponse creates a token response from cache
func CreateStorageTokenResponse(accessToken IAccessToken, refreshToken Credential, idToken Credential, account *Account) *StorageTokenResponse {
	tr := &StorageTokenResponse{accessToken, refreshToken, idToken, account}
	return tr
}

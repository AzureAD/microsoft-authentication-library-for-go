// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

// HTTPManager represents MSAL's HTTP Client.
type HTTPManager interface {
	Get(url string, requestHeaders map[string]string) (HTTPManagerResponse, error)
	Post(url string, body string, requestHeaders map[string]string) (HTTPManagerResponse, error)
}

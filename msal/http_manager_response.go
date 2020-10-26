// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msal

// HTTPManagerResponse is an interface representing MSAL's HTTP Response object.
type HTTPManagerResponse interface {
	GetResponseCode() int
	GetResponseData() string
	GetHeaders() map[string]string
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package msal provides the Microsoft Authentication Library (MSAL) for the Go language.
package msal

import "net/http"

// HTTPClient represents an HTTP transport used to send HTTP requests and receive responses.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

const (
	// default AAD authority host
	authorityPublicCloud = "https://login.microsoftonline.com/common"
)

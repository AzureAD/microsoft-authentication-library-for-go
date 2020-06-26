// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

type IHTTPManager interface {
	Get(url string, requestHeaders map[string]string) (IHTTPManagerResponse, error)
	Post(url string, body string, requestHeaders map[string]string) (IHTTPManagerResponse, error)
}

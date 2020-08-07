// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//HTTPManager is an interface representing MSAL's HTTP Client.
// To implement your own version of this interface, you would need to implement these two methods.
type HTTPManager interface {
	Get(url string, requestHeaders map[string]string) (HTTPManagerResponse, error)
	Post(url string, body string, requestHeaders map[string]string) (HTTPManagerResponse, error)
}

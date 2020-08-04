// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//HTTPManagerResponse is an interface representing MSAL's HTTP Response
type HTTPManagerResponse interface {
	GetResponseCode() int
	GetResponseData() string
	GetHeaders() map[string]string
}

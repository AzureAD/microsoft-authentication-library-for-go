// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

//HTTPManagerResponse is an interface representing MSAL's HTTP Response object.
//To implement your own version of this interface, you would need to implement the three methods.
type HTTPManagerResponse interface {
	GetResponseCode() int
	GetResponseData() string
	GetHeaders() map[string]string
}

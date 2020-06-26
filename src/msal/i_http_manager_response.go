// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

type IHTTPManagerResponse interface {
	GetResponseCode() int
	GetResponseData() string
	GetHeaders() map[string]string
}

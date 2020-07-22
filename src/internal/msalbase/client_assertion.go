// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

type ClientAssertion struct {
	ClientAssertionJWT string
}

func CreateClientAssertionFromJWT(jwt string) *ClientAssertion {
	return &ClientAssertion{ClientAssertionJWT: jwt}
}

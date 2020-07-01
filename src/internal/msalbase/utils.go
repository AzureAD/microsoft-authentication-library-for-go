// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"strconv"
	"strings"
	"time"
)

//ConvertStrUnixToUTCTime converts a string representation of unix time to a UTC timestamp
func ConvertStrUnixToUTCTime(unixTime string) (time.Time, error) {
	timeInt, err := strconv.ParseInt(unixTime, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(timeInt, 0).UTC(), nil
}

//ConcatenateScopes combines all scopes into one space-separated string
func ConcatenateScopes(scopes []string) string {
	return strings.Join(scopes, DefaultScopeSeparator)
}

func SplitScopes(scopes string) []string {
	return strings.Split(scopes, DefaultScopeSeparator)
}

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

//SplitScopes splits a space-separated string of scopes to a list
func SplitScopes(scopes string) []string {
	return strings.Split(scopes, DefaultScopeSeparator)
}

func ExtractExistingOrEmptyString(j map[string]interface{}, key string) string {
	if val, ok := j[key]; ok {
		if str, ok := val.(string); ok {
			delete(j, key)
			return str
		}
	}
	delete(j, key)
	return ""
}

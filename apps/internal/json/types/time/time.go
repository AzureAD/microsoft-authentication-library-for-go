// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package time provides for custom types to translate time from JSON and other formats
// into time.Time objects.
package time

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Unix provides a type that can marshal and unmarshal a string representation
// of the unix epoch into a time.Time object.
type Unix struct {
	T time.Time
}

// MarshalJSON implements encoding/json.MarshalJSON().
func (u Unix) MarshalJSON() ([]byte, error) {
	if u.T.IsZero() {
		return []byte(""), nil
	}
	return []byte(fmt.Sprintf("%q", strconv.FormatInt(u.T.Unix(), 10))), nil
}

// UnmarshalJSON implements encoding/json.UnmarshalJSON().
func (u *Unix) UnmarshalJSON(b []byte) error {
	i, err := strconv.Atoi(strings.Trim(string(b), `"'`))
	if err != nil {
		return fmt.Errorf("unix time(%s) could not be converted from string to int: %w", string(b), err)
	}
	u.T = time.Unix(int64(i), 0)
	return nil
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Package time provides for custom types to translate time from JSON and other formats
// into time.Time objects.
package time

import (
	"fmt"
	"regexp"
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
	i, err := strconv.Atoi(strings.Trim(string(b), `"`))
	if err != nil {
		return fmt.Errorf("unix time(%s) could not be converted from string to int: %w", string(b), err)
	}
	u.T = time.Unix(int64(i), 0)
	return nil
}

// DurationTime provides a type that can marshal and unmarshal a string representation
// of a duration from now into a time.Time object.
// Note: I'm not sure this is the best way to do this. What happens is we get a field
// called "expires_in" that represents the seconds from now that this expires. We
// turn that into a time we call .ExpiresOnCalculated. But maybe we should be recording
// when the token was received at .TokenRecieved and .ExpiresIn should remain as a duration.
// Then we could have a method called ExpiresOnCalculated().  Honestly, the whole thing is
// bad because the server doesn't return a concrete time. I think this is
// cleaner, but its not great either.
type DurationTime struct {
	T time.Time
}

// MarshalJSON implements encoding/json.MarshalJSON().
func (d DurationTime) MarshalJSON() ([]byte, error) {
	if d.T.IsZero() {
		return []byte(""), nil
	}

	dt := time.Until(d.T)
	return []byte(fmt.Sprintf("%d", int64(dt*time.Second))), nil
}

// UnmarshalJSON custom unmarshaler for DurationTime
func (t *DurationTime) UnmarshalJSON(b []byte) error {
	// Remove the quotes around the JSON string
	str := strings.Trim(string(b), `"`)

	// Try parsing as Unix timestamp (seconds since the Unix epoch)
	if len(str) == 10 {
		if unixTimestamp, err := strconv.ParseInt(str, 10, 64); err == nil {
			t.T = time.Unix(unixTimestamp, 0)
			return nil
		}
	}

	// Try parsing as ISO 8601 format (e.g., "2024-10-18T19:51:37.0000000+00:00")
	iso8601Layout := "2006-01-02T15:04:05.9999999-07:00"
	if parsedTime, err := time.Parse(iso8601Layout, str); err == nil {
		t.T = parsedTime
		return nil
	}

	// Try parsing as MM/dd/yyyy HH:mm:ss format (e.g., "10/18/2024 19:51:37")
	// Create regex pattern for MM/dd/yyyy HH:mm:ss
	mmddyyyyLayout := `^(\d{2})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2})$`
	if matched, _ := regexp.MatchString(mmddyyyyLayout, str); matched {
		parsedTime, err := time.Parse("01/02/2006 15:04:05", str)
		if err == nil {
			t.T = parsedTime
			return nil
		}
	}

	// Try parsing as yyyy-MM-dd HH:mm:ss format (e.g., "2024-10-18 19:51:37")
	if parsedTime, err := time.Parse("2006-01-02 15:04:05", str); err == nil {
		t.T = parsedTime
		return nil
	}

	i, err := strconv.Atoi(str)
	if err != nil {
		return fmt.Errorf("unix time(%s) could not be converted from string to int: %w", string(b), err)
	}
	t.T = time.Now().Add(time.Duration(i) * time.Second)
	return nil

}

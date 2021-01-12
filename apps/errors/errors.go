// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package errors

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/kylelemons/godebug/pretty"
)

var prettyConf = &pretty.Config{
	IncludeUnexported: false,
	SkipZeroFields:    true,
	TrackCycles:       true,
	Formatter: map[reflect.Type]interface{}{
		reflect.TypeOf((*io.ReadCloser)(nil)).Elem(): func(rc io.ReadCloser) string {
			b, err := ioutil.ReadAll(rc)
			if err != nil {
				return "could not read io.ReadCloser content"
			}
			return string(b)
		},
	},
}

type verboser interface {
	Verbose() string
}

// Verbose prints the most verbose error that the error message has.
func Verbose(err error) string {
	build := strings.Builder{}
	for {
		if err == nil {
			break
		}
		if v, ok := err.(verboser); ok {
			build.WriteString(v.Verbose())
		} else {
			build.WriteString(err.Error())
		}
		err = errors.Unwrap(err)
	}
	return build.String()
}

// New is equivalent to errors.New().
func New(text string) error {
	return errors.New(text)
}

// CallErr represents an HTTP call error. Has a Verbose() method that allows getting the
// http.Request and Response objects. Implements error.
type CallErr struct {
	Req  *http.Request
	Resp *http.Response
	Err  error
}

// Errors implements error.Error().
func (e CallErr) Error() string {
	return e.Err.Error()
}

// Verbose prints a versbose error message with the request or response.
func (e CallErr) Verbose() string {
	e.Resp.Request = nil // This brings in a bunch of TLS crap we don't need
	return fmt.Sprintf("%s:\nRequest:\n%s\nResponse:\n%s", e.Err, prettyConf.Sprint(e.Req), prettyConf.Sprint(e.Resp))
}

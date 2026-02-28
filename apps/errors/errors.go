// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package errors

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

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
	Req *http.Request
	// Resp contains response body
	Resp *http.Response
	Err  error
}

type InvalidJsonErr struct {
	Err error
}

// Errors implements error.Error().
func (e CallErr) Error() string {
	return e.Err.Error()
}

// Errors implements error.Error().
func (e InvalidJsonErr) Error() string {
	return e.Err.Error()
}

// Verbose prints a versbose error message with the request or response.
func (e CallErr) Verbose() string {
	e.Resp.Request = nil // This brings in a bunch of TLS crap we don't need
	e.Resp.TLS = nil     // Same
	return fmt.Sprintf("%s:\nRequest:\n%s\nResponse:\n%s", e.Err, dumpRequest(e.Req), dumpResponse(e.Resp))
}

func dumpRequest(req *http.Request) string {
	if req == nil {
		return "nil"
	}

	b, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return "could not dump request"
	}
	if req.Body != nil {
		req.Body = io.NopCloser(strings.NewReader(""))
	}
	return string(b)
}

func dumpResponse(resp *http.Response) string {
	if resp == nil {
		return "nil"
	}

	b, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return "could not dump response"
	}
	if resp.Body != nil {
		resp.Body = io.NopCloser(strings.NewReader(""))
	}
	return string(b)
}

// Is reports whether any error in errors chain matches target.
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in errors chain that matches target,
// and if so, sets target to that error value and returns true.
// Otherwise, it returns false.
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

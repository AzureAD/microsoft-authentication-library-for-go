// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package errors

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
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
	var b strings.Builder
	fmt.Fprintf(&b, "{Method:     %q,\n", req.Method)
	fmt.Fprintf(&b, " URL:        {Scheme:   %q,\n", req.URL.Scheme)
	fmt.Fprintf(&b, "              Host:     %q,\n", req.URL.Host)
	fmt.Fprintf(&b, "              Path:     %q,\n", req.URL.Path)
	fmt.Fprintf(&b, "              RawQuery: %q},\n", req.URL.RawQuery)
	fmt.Fprintf(&b, " Proto:      %q,\n", req.Proto)
	fmt.Fprintf(&b, " ProtoMajor: %d,\n", req.ProtoMajor)
	fmt.Fprintf(&b, " ProtoMinor: %d,\n", req.ProtoMinor)
	fmt.Fprintf(&b, " Header:     %s,\n", formatHeaders(req.Header, "              "))
	fmt.Fprintf(&b, " Host:       %q}", req.Host)
	return b.String()
}

func dumpResponse(resp *http.Response) string {
	if resp == nil {
		return "nil"
	}
	var bodyStr string
	if resp.Body != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err == nil {
			bodyStr = string(bodyBytes)
		}
		resp.Body = io.NopCloser(strings.NewReader(""))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "{Status:        %q,\n", resp.Status)
	fmt.Fprintf(&b, " StatusCode:    %d,\n", resp.StatusCode)
	fmt.Fprintf(&b, " Proto:         %q,\n", resp.Proto)
	fmt.Fprintf(&b, " ProtoMajor:    %d,\n", resp.ProtoMajor)
	fmt.Fprintf(&b, " ProtoMinor:    %d,\n", resp.ProtoMinor)
	fmt.Fprintf(&b, " Header:        %s,\n", formatHeaders(resp.Header, "                 "))
	if bodyStr == "" {
		fmt.Fprintf(&b, " Body:          {},\n")
	} else {
		fmt.Fprintf(&b, " Body:          %q,\n", bodyStr)
	}
	fmt.Fprintf(&b, " ContentLength: %d}", resp.ContentLength)
	return b.String()
}

func formatHeaders(header http.Header, indent string) string {
	if len(header) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(header))
	maxLen := 0
	for k := range header {
		keys = append(keys, k)
		if len(k) > maxLen {
			maxLen = len(k)
		}
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := make([]string, len(header[k]))
		for i, v := range header[k] {
			vals[i] = fmt.Sprintf("%q", v)
		}
		parts = append(parts, fmt.Sprintf("%-*s [%s]", maxLen+1, k+":", strings.Join(vals, ", ")))
	}
	if len(parts) == 1 {
		return "{" + parts[0] + "}"
	}
	return "{" + strings.Join(parts, ",\n"+indent) + "}"
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

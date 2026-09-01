// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package errors

import (
	"errors"
	"fmt"
	"io"
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
		reflect.TypeOf((*io.Reader)(nil)).Elem(): func(r io.Reader) string {
			b, err := io.ReadAll(r)
			if err != nil {
				return "could not read io.Reader content"
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
	return fmt.Sprintf("%s:\nRequest:\n%s\nResponse:\n%s", e.Err, prettyConf.Sprint(e.Req), prettyConf.Sprint(e.Resp))
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

// MtlsPoPTokenTypeMismatchError indicates the caller requested a mutual-TLS proof-of-possession
// (mtls_pop) token but the identity provider returned a different token_type (for example
// "Bearer"). mTLS PoP is a security primitive, so rather than surface a token that is not actually
// certificate-bound, MSAL fails closed with this error.
//
// It normally means the identity provider or the tenant is not configured to issue the requested
// token type, so it is a configuration problem to diagnose. Retrying without the mTLS PoP option
// produces an unbound token and is a separate, deliberately adopted application policy of accepting a
// weaker credential; it is not a sanctioned reaction to this error.
//
// Detect it with errors.As, passing the address of a value of this type:
//
//	var mismatch errors.MtlsPoPTokenTypeMismatchError
//	if errors.As(err, &mismatch) {
//		log.Printf("tenant returned %q, wanted %q", mismatch.Actual, mismatch.Expected)
//	}
//
// The reflexive Go idiom of declaring a pointer target
//
//	var mismatch *errors.MtlsPoPTokenTypeMismatchError // wrong: never matches
//
// compiles, does not panic, and always returns false. MSAL always returns this error as a value, so
// there is never a *MtlsPoPTokenTypeMismatchError in the chain for errors.As to assign from. The
// pointer type does satisfy error, because a method declared on a value receiver is in the method
// set of both T and *T, which is exactly why the call fails silently instead of panicking. Use the
// value form above.
//
// Mirrors MSAL .NET's "token_type_mismatch" (MsalClientException).
type MtlsPoPTokenTypeMismatchError struct {
	// Expected is the token_type the request required (always "mtls_pop").
	Expected string
	// Actual is the token_type the identity provider returned. It may be empty if the response
	// omitted token_type.
	Actual string
}

// Error implements error on a value receiver. That is deliberate, and it is paired with an invariant
// at the raise site: this type is always returned as a value, never as a pointer. Returning it by
// pointer, or moving Error to a pointer receiver (which would force the raise site to a pointer),
// would silently break every caller using the errors.As form the type's doc comment prescribes.
func (e MtlsPoPTokenTypeMismatchError) Error() string {
	actual := e.Actual
	if actual == "" {
		actual = "<missing>"
	}
	return fmt.Sprintf(
		"requested token_type %q but the identity provider returned %q; the access token is not certificate-bound",
		e.Expected, actual,
	)
}

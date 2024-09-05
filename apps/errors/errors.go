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

// Errors implements error.Error().
func (e CallErr) Error() string {
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

// Constants for Managed Identity Errors
const (
	MiError = "[Managed Identity Error]\nError Code: %s\nSource Type: %s\nError Message: %s"

	/* Managed Identity Error Codes */
	// A required value is missing from the managed identity response.
	MiErrorCodeResponse = "invalid_managed_identity_response"

	// Managed Identity error response was received.
	MiErrorCodeRequestFailed = "managed_identity_request_failed"

	// Managed Identity endpoint is not reachable.
	MiErrorCodeUnreachableNetwork = "managed_identity_unreachable_network"

	// Unknown error response received.
	MiErrorCodeUnknownError = "unknown_managed_identity_error"

	// Invalid managed identity endpoint.
	MiErrorCodeInvalidEndpoint = "invalid_managed_identity_endpoint"

	// User assigned managed identity is not supported for this source.
	MiErrorCodeUserAssignedNotSupported = "user_assigned_managed_identity_not_supported"

	// User assigned managed identity is not configurable at runtime for service fabric.
	MiErrorCodeUserAssignedNotConfigurableAtRuntime = "user_assigned_managed_identity_not_configurable_at_runtime"

	/* Managed Identity Error Messages */
	ManagedIdentityEndpointInvalidURIError              = "[Managed Identity] The environment variable %s contains an invalid Uri %s in %s managed identity source."
	ManagedIdentityNoChallengeError                     = "[Managed Identity] Did not receive expected WWW-Authenticate header in the response from Azure Arc Managed Identity Endpoint."
	ManagedIdentityInvalidChallenge                     = "[Managed Identity] The WWW-Authenticate header in the response from Azure Arc Managed Identity Endpoint did not match the expected format."
	ManagedIdentityPlatformNotSupported                 = "[Managed Identity] This managed identity source is not available on this platform."
	ManagedIdentityInvalidFilePath                      = "[Managed Identity] The file on the file path in the WWW-Authenticate header is not secure or could not be found."
	ManagedIdentityUserAssignedNotConfigurableAtRuntime = "[Managed Identity] Service Fabric user assigned managed identity ClientId or ResourceId is not configurable at runtime."
	ManagedIdentityUserAssignedNotSupported             = "[Managed Identity] User assigned identity is not supported by the %s Managed Identity. To authenticate with the system assigned identity use ManagedIdentityApplication.builder(ManagedIdentityId.systemAssigned()).build()."
	ManagedIdentityUnexpectedErrorResponse              = "[Managed Identity] The error response was either empty or could not be parsed."
	ManagedIdentityNoResponseReceived                   = "[Managed Identity] Authentication unavailable. No response received"
	ManagedIdentityInvalidResponse                      = "[Managed Identity] Invalid response, the authentication response received did not contain the expected fields."
	ManagedIdentityScopesRequired                       = "[Managed Identity] At least one scope needs to be requested for this authentication flow."
	ManagedIdentityDefaultMessage                       = "[Managed Identity] Service request failed."
	ManagedIdentityIdentityUnavailableError             = "[Managed Identity] Authentication unavailable. The requested identity has not been assigned to this resource."
	ManagedIdentityGatewayError                         = "[Managed Identity] Authentication unavailable. The request failed due to a gateway error."
)

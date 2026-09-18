// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows
// +build windows

package managedidentity

import (
	"errors"
	"testing"
)

type typedProviderError struct {
	reason string
}

func (e *typedProviderError) Error() string {
	return e.reason
}

type loadErrorProvider struct {
	handle uintptr
	err    error
}

func (p loadErrorProvider) LoadAttestationLibrary() (uintptr, error) {
	return p.handle, p.err
}

func TestAttestationProviderErrorMatchesSentinelAndOriginalCause(t *testing.T) {
	cause := &typedProviderError{reason: "provider verification failed"}
	_, err := loadAttestationLib(loadErrorProvider{err: cause})
	if !errors.Is(err, ErrAttestationUnavailable) {
		t.Fatalf("error = %v, want ErrAttestationUnavailable", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error = %v, want original cause", err)
	}
	var typed *typedProviderError
	if !errors.As(err, &typed) || typed != cause {
		t.Fatalf("errors.As found %#v, want original typed cause %#v", typed, cause)
	}
	var wrapped *attestationProviderError
	if !errors.As(err, &wrapped) {
		t.Fatalf("error = %v, want attestationProviderError", err)
	}
}

func TestAttestationProviderSentinelIsNotWrappedAgain(t *testing.T) {
	cause := errors.New("provider detail")
	providerErr := &attestationProviderError{cause: cause}
	_, err := loadAttestationLib(loadErrorProvider{err: providerErr})
	if err != providerErr {
		t.Fatalf("error = %v, want the original provider error without another wrapper", err)
	}
	if !errors.Is(err, ErrAttestationUnavailable) || !errors.Is(err, cause) {
		t.Fatalf("error = %v, want sentinel and original cause", err)
	}
	var wrapped *attestationProviderError
	if !errors.As(err, &wrapped) || wrapped != providerErr {
		t.Fatalf("error = %v, want the original provider wrapper", err)
	}
	if next := errors.Unwrap(wrapped); next != cause {
		t.Fatalf("provider wrapper unwraps to %v, want %v", next, cause)
	}
}

func TestAttestationProviderNilAndZeroHandleFailUnavailable(t *testing.T) {
	for _, test := range []struct {
		name     string
		provider AttestationProvider
	}{
		{"nil provider", nil},
		{"zero handle", loadErrorProvider{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lib, err := loadAttestationLib(test.provider)
			if lib != nil {
				t.Fatalf("library = %#v, want nil", lib)
			}
			if !errors.Is(err, ErrAttestationUnavailable) {
				t.Fatalf("error = %v, want ErrAttestationUnavailable", err)
			}
		})
	}
}

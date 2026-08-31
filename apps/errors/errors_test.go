// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package errors

import (
	stderrors "errors"
	"fmt"
	"testing"
)

// TestMtlsPoPTokenTypeMismatchErrorAs pins the errors.As form the type's doc comment prescribes, and
// the reason it prescribes it: MSAL always returns this error as a value, so a pointer target has no
// *MtlsPoPTokenTypeMismatchError in the chain to match. The pointer form compiles and does not panic
// - a method on a value receiver is in the method set of both T and *T, so *T does satisfy error -
// it just silently returns false. A caller who writes it gets no diagnostic at all, just an mTLS PoP
// mismatch they never see. That the production raise site really does return a value is pinned
// end to end by TestFromClientCertificateMtlsPoPTokenTypeMismatch in the accesstokens package.
func TestMtlsPoPTokenTypeMismatchErrorAs(t *testing.T) {
	raised := MtlsPoPTokenTypeMismatchError{Expected: "mtls_pop", Actual: "Bearer"}
	wrapped := fmt.Errorf("acquiring a token failed: %w", raised)

	t.Run("value target matches", func(t *testing.T) {
		var mismatch MtlsPoPTokenTypeMismatchError
		if !stderrors.As(wrapped, &mismatch) {
			t.Fatal("errors.As with a value target did not match; the documented form must work")
		}
		if mismatch.Expected != "mtls_pop" || mismatch.Actual != "Bearer" {
			t.Errorf("errors.As populated %+v, want the raised value", mismatch)
		}
	})

	t.Run("As helper matches the value target", func(t *testing.T) {
		var mismatch MtlsPoPTokenTypeMismatchError
		if !As(wrapped, &mismatch) {
			t.Fatal("this package's As helper did not match a value target")
		}
	})

	t.Run("pointer target never matches", func(t *testing.T) {
		var mismatch *MtlsPoPTokenTypeMismatchError
		if stderrors.As(wrapped, &mismatch) {
			t.Fatal("errors.As matched a pointer target, so the value form the type's doc comment prescribes is no longer the correct one")
		}
	})

	t.Run("unwrapped value matches too", func(t *testing.T) {
		var mismatch MtlsPoPTokenTypeMismatchError
		if !stderrors.As(error(raised), &mismatch) {
			t.Fatal("errors.As did not match an unwrapped value")
		}
	})
}

func TestMtlsPoPTokenTypeMismatchErrorMessage(t *testing.T) {
	for _, test := range []struct {
		name string
		err  MtlsPoPTokenTypeMismatchError
		want string
	}{
		{
			name: "provider returned another type",
			err:  MtlsPoPTokenTypeMismatchError{Expected: "mtls_pop", Actual: "Bearer"},
			want: `requested token_type "mtls_pop" but the identity provider returned "Bearer"; the access token is not certificate-bound`,
		},
		{
			name: "provider omitted token_type",
			err:  MtlsPoPTokenTypeMismatchError{Expected: "mtls_pop"},
			want: `requested token_type "mtls_pop" but the identity provider returned "<missing>"; the access token is not certificate-bound`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.err.Error(); got != test.want {
				t.Errorf("Error() = %q, want %q", got, test.want)
			}
		})
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build go1.21

package managedidentity

import (
	"crypto/tls"
	"errors"
)

// isCertificateAlert reports whether err carries a TLS alert that names the
// client certificate as the reason the handshake failed.
//
// Go 1.21 gave alerts a typed representation, so the alert code is read
// directly rather than inferred from the message. MSAL .NET reaches the same
// conclusion by catching AuthenticationException, which is broader still: it
// treats every handshake failure as a reason to re-mint. Matching a specific
// set of alerts keeps an unrelated handshake problem, such as a protocol
// version mismatch, from being misread as a stale certificate.
func isCertificateAlert(err error) bool {
	var alert tls.AlertError
	if !errors.As(err, &alert) {
		// A wrapped error that never reaches an AlertError can still be an
		// alert from a transport that formats its own message, so the text
		// check remains the backstop.
		return certificateAlertText(err)
	}
	switch uint8(alert) {
	case 40, // handshake_failure
		42,  // bad_certificate
		43,  // unsupported_certificate
		44,  // certificate_revoked
		45,  // certificate_expired
		46,  // certificate_unknown
		48,  // unknown_ca
		49,  // access_denied
		116: // certificate_required
		return true
	}
	return false
}

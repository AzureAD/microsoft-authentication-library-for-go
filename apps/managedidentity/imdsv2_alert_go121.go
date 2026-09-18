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
// directly rather than inferred from the message. MSAL .NET reaches a broader
// conclusion by catching AuthenticationException, which treats every handshake
// failure as a reason to re-mint. Matching only alerts that name a certificate
// keeps an unrelated handshake problem from being misread as a stale one.
//
// handshake_failure (40) is deliberately absent. It is the alert a server sends
// when it cannot agree on a protocol version or a cipher suite, which says
// nothing about the client certificate; including it would rotate a healthy
// binding certificate - and spend an /issuecredential call against a
// rate-limited service - over a TLS configuration mismatch. A server that
// really is refusing the certificate has bad_certificate, certificate_revoked,
// certificate_expired, certificate_unknown, unknown_ca, unsupported_certificate,
// access_denied and certificate_required to say so, and those are matched.
func isCertificateAlert(err error) bool {
	var alert tls.AlertError
	if !errors.As(err, &alert) {
		// A wrapped error that never reaches an AlertError can still be an
		// alert from a transport that formats its own message, so the text
		// check remains the backstop.
		return certificateAlertText(err)
	}
	switch uint8(alert) {
	case 42, // bad_certificate
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

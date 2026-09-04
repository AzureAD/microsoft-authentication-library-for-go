// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !go1.21

package managedidentity

// isCertificateAlert reports whether err carries a TLS alert that names the
// client certificate as the reason the handshake failed.
//
// crypto/tls gained a typed alert in Go 1.21. Below that the message is the
// only signal available, so the text form is used; see the go1.21 build of this
// file for the typed implementation and the reasoning behind the alert set.
func isCertificateAlert(err error) bool {
	return certificateAlertText(err)
}

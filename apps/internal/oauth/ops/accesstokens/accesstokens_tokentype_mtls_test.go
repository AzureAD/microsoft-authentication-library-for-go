// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// respWritingCaller is a URLCaller that writes a canned TokenResponse (token_type + access_token) so
// the non-testing doTokenResp path (Validate plus the mTLS PoP token_type guard) can be exercised
// without real network IO.
type respWritingCaller struct {
	tokenType string
	gotCert   *tls.Certificate
}

func (c *respWritingCaller) URLFormCall(ctx context.Context, endpoint string, qv url.Values, resp interface{}) error {
	return c.writeResp(resp)
}

func (c *respWritingCaller) URLFormCallWithCertificate(ctx context.Context, endpoint string, qv url.Values, resp interface{}, cert *tls.Certificate) error {
	c.gotCert = cert
	return c.writeResp(resp)
}

func (c *respWritingCaller) writeResp(resp interface{}) error {
	tr, ok := resp.(*TokenResponse)
	if !ok {
		return fmt.Errorf("respWritingCaller: unexpected resp type %T", resp)
	}
	tr.AccessToken = "an_access_token"
	tr.TokenType = c.tokenType
	tr.ExpiresOn = time.Now().Add(time.Hour)
	return nil
}

// TestFromClientCertificateMtlsPoPTokenTypeMismatch verifies MSAL fails closed when the identity
// provider downgrades an mtls_pop request to a Bearer token, mirroring MSAL .NET's
// "token_type_mismatch". The error must be detectable with errors.As.
func TestFromClientCertificateMtlsPoPTokenTypeMismatch(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)

	// Server downgrades: returns a Bearer token for an mtls_pop request.
	fake := &respWritingCaller{tokenType: authority.AccessTokenTypeBearer}
	client := Client{Comm: fake, testing: false}

	_, err := client.FromClientCertificate(context.Background(), authParams)
	if err == nil {
		t.Fatal("expected an error when the server downgrades mtls_pop to Bearer, got nil")
	}
	var mism msalerrors.MtlsPoPTokenTypeMismatchError
	if !msalerrors.As(err, &mism) {
		t.Fatalf("expected MtlsPoPTokenTypeMismatchError, got %T: %v", err, err)
	}
	if mism.Expected != authority.AccessTokenTypeMtlsPoP || mism.Actual != authority.AccessTokenTypeBearer {
		t.Fatalf("mismatch = {Expected:%q Actual:%q}, want {mtls_pop, Bearer}", mism.Expected, mism.Actual)
	}
}

// TestFromClientCertificateMtlsPoPTokenTypeHonored verifies the guard passes when the identity
// provider returns token_type=mtls_pop as requested.
func TestFromClientCertificateMtlsPoPTokenTypeHonored(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)

	fake := &respWritingCaller{tokenType: authority.AccessTokenTypeMtlsPoP}
	client := Client{Comm: fake, testing: false}

	if _, err := client.FromClientCertificate(context.Background(), authParams); err != nil {
		t.Fatalf("unexpected error for an honored mtls_pop response: %v", err)
	}
}

// TestUnrequestedMtlsPoPTokenTypeRejected covers the inverse mismatch: the caller did not ask for
// proof-of-possession but the identity provider returned a certificate-bound token anyway.
//
// This is the bearer-over-mTLS shape, which presents the certificate on the handshake but requests
// an ordinary bearer token. Accepting a mtls_pop response there caches a certificate-bound token
// under the bearer cache key and hands it back with no BindingCertificate, because AuthResult only
// populates that field for an mTLS PoP request. The caller has nothing to present, and the resource
// rejects the token on a connection that does not carry the bound certificate. Only the
// request/response pair can detect it, so it has to be caught here rather than surfacing later as an
// opaque 401.
func TestUnrequestedMtlsPoPTokenTypeRejected(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)
	// Bearer over mTLS: the binding certificate is still presented on the handshake, but the request
	// does not ask for a certificate-bound token.
	authParams.IsMtlsPoP = false
	authParams.AuthnScheme = nil

	fake := &respWritingCaller{tokenType: authority.AccessTokenTypeMtlsPoP}
	client := Client{Comm: fake, testing: false}

	_, err := client.FromClientCertificate(context.Background(), authParams)
	if err == nil {
		t.Fatal("expected an error when the server returns mtls_pop for a request that did not ask for it")
	}
	if !strings.Contains(err.Error(), authority.AccessTokenTypeMtlsPoP) {
		t.Errorf("error should name the token type it rejected, got: %v", err)
	}
	if !strings.Contains(err.Error(), "WithMtlsProofOfPossession") {
		t.Errorf("error should name the remedy, got: %v", err)
	}
}

// TestUnrequestedBearerTokenTypeAccepted guards the guard above: an ordinary bearer response to an
// ordinary request must still pass. Without this, tightening the check into a blanket rejection of
// every response whose token_type is not mtls_pop would go unnoticed.
func TestUnrequestedBearerTokenTypeAccepted(t *testing.T) {
	cert := selfSignedTLSCert(t)
	authParams := mtlsAuthParams(cert)
	authParams.IsMtlsPoP = false
	authParams.AuthnScheme = nil

	fake := &respWritingCaller{tokenType: authority.AccessTokenTypeBearer}
	client := Client{Comm: fake, testing: false}

	if _, err := client.FromClientCertificate(context.Background(), authParams); err != nil {
		t.Fatalf("a bearer response to a non-PoP request must be accepted, got: %v", err)
	}
}

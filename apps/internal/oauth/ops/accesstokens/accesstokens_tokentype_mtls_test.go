// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
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

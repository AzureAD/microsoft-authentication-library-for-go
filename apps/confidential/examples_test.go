// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	internalTime "github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/json/types/time"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/accesstokens"
)

func ExampleNewCredFromCert_pem() {
	b, err := ioutil.ReadFile("key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// This extracts our public certificates and private key from the PEM file.
	// The private key must be in PKCS8 format. If it is encrypted, the second argument
	// must be password to decode.
	certs, priv, err := CertFromPEM(b, "")
	if err != nil {
		log.Fatal(err)
	}

	// PEM files can have multiple certs. This is usually for certificate chaining where roots
	// sign to leafs. Useful for TLS, not for this use case.
	if len(certs) > 1 {
		log.Fatal("too many certificates in PEM file")
	}

	cred := NewCredFromCert(certs[0], priv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cred) // Simply here so cred is used, otherwise won't compile.
}

// ExampleAcquireTokenByCredential gives an example of acquiring token by credential.
// First attempt is made at getting the token from the cache using AcquireTokenSilent.
// If the token is missing from the cache, then it will fetch the token using AcquireTokenByCredential and cache it.
func ExampleAcquireTokenByCredential() {
	var tokenScope = []string{"the_scope"}
	client, err := FakeClient(accesstokens.TokenResponse{
		AccessToken:   token,
		RefreshToken:  refresh,
		ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		IDToken: accesstokens.IDToken{
			PreferredUsername: "fakeuser@fakeplace.fake",
			Name:              "fake person",
			Oid:               "123-456",
			TenantID:          "fake",
			Subject:           "nothing",
			Issuer:            "https://fake_authority/fake",
			Audience:          "abc-123",
			ExpirationTime:    time.Now().Add(time.Hour).Unix(),
			IssuedAt:          time.Now().Add(-5 * time.Minute).Unix(),
			NotBefore:         time.Now().Add(-5 * time.Minute).Unix(),
			// NOTE: this is an invalid JWT however this doesn't cause a failure.
			// it simply falls back to calling Token.Refresh() which will obviously succeed.
			RawToken: "fake.raw.token",
		},
		ClientInfo: accesstokens.ClientInfo{
			UID:  "123-456",
			UTID: "fake",
		},
	}, "fake_secret")

	if err != nil {
		log.Fatalf("ExampleAcquireTokenByCredential: intializing client %v", err)
	}

	ctx := context.Background()
	token, err := client.AcquireTokenSilent(ctx, tokenScope)
	if err != nil {
		token, err = client.AcquireTokenByCredential(context.Background(), tokenScope)
		if err != nil {
			log.Fatalf("ExampleAcquireTokenByCredential: acquring token by credential %v", err)
		}
		fmt.Println(token)
		return
	}
	fmt.Println(token)

}

// ExampleAcquireTokenByAuthCode gives an example of acquiring token by auth code.
// First attempt is made at getting the token from the cache using AcquireTokenSilent.
// If the token is missing from the cache, then it will fetch the token using AcquireTokenByAuthCode and cache it.
func ExampleAcquireTokenByAuthCode() {
	var tokenScope = []string{"the_scope"}
	client, err := FakeClient(accesstokens.TokenResponse{
		AccessToken:   token,
		RefreshToken:  refresh,
		ExpiresOn:     internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		ExtExpiresOn:  internalTime.DurationTime{T: time.Now().Add(1 * time.Hour)},
		GrantedScopes: accesstokens.Scopes{Slice: tokenScope},
		IDToken: accesstokens.IDToken{
			PreferredUsername: "fakeuser@fakeplace.fake",
			Name:              "fake person",
			Oid:               "123-456",
			TenantID:          "fake",
			Subject:           "nothing",
			Issuer:            "https://fake_authority/fake",
			Audience:          "abc-123",
			ExpirationTime:    time.Now().Add(time.Hour).Unix(),
			IssuedAt:          time.Now().Add(-5 * time.Minute).Unix(),
			NotBefore:         time.Now().Add(-5 * time.Minute).Unix(),
			// NOTE: this is an invalid JWT however this doesn't cause a failure.
			// it simply falls back to calling Token.Refresh() which will obviously succeed.
			RawToken: "fake.raw.token",
		},
		ClientInfo: accesstokens.ClientInfo{
			UID:  "123-456",
			UTID: "fake",
		},
	}, "fake_secret")

	if err != nil {
		log.Fatalf("ExampleAcquireTokenByAuthCode: intializing client %v", err)
	}

	ctx := context.Background()
	token, err := client.AcquireTokenSilent(ctx, tokenScope)
	if err != nil {
		token, err = client.AcquireTokenByAuthCode(context.Background(), "xxxcodexxx", "http://localhost/auth_code", tokenScope)
		if err != nil {
			log.Fatalf("ExampleAcquireTokenByAuthCode: acquring token by credential %v", err)
		}
		fmt.Println(token)
		return
	}
	fmt.Println(token)

}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/mock"
)

func TestCertificateMtlsCacheHitDoesNotResolveTokenEndpoint(t *testing.T) {
	certs, key := loadTestCert(t)
	cred, err := NewCredFromCert(certs, key)
	if err != nil {
		t.Fatal(err)
	}
	const (
		tenant = "tenant"
		lmo    = "login.microsoftonline.com"
	)
	cache := make(testCache)
	online := mock.NewClient()
	online.AppendResponse(mock.WithBody(mock.GetTenantDiscoveryBody(lmo, tenant)))
	online.AppendResponse(mock.WithBody(mock.GetAccessTokenBody("cached-token", "", "", "", 3600, 0)))
	first, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(online),
		withTestMtlsClient(mockMtlsFactory(online)),
		WithInstanceDiscovery(false),
		WithSendCertificateOverMtls(),
		WithCache(&cache),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.AcquireTokenByCredential(context.Background(), tokenScope); err != nil {
		t.Fatal(err)
	}

	offline := &countingClient{}
	var factoryCalls int32
	second, err := New(fmt.Sprintf(authorityFmt, lmo, tenant), fakeClientID, cred,
		WithHTTPClient(offline),
		withTestMtlsClient(func(tls.Certificate) *http.Client {
			atomic.AddInt32(&factoryCalls, 1)
			return &http.Client{}
		}),
		WithInstanceDiscovery(false),
		WithSendCertificateOverMtls(),
		WithCache(&cache),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := second.AcquireTokenByCredential(context.Background(), tokenScope)
	if err != nil {
		t.Fatalf("fresh client couldn't load cached token without discovery: %v", err)
	}
	if result.AccessToken != "cached-token" {
		t.Fatalf("AccessToken = %q, want cached-token", result.AccessToken)
	}
	if offline.count() != 0 || atomic.LoadInt32(&factoryCalls) != 0 {
		t.Errorf("cache hit made %d HTTP calls and %d mTLS factory calls", offline.count(), factoryCalls)
	}
}

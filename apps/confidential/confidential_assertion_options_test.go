// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package confidential

import (
	"context"
	"reflect"
	"testing"
)

func TestAssertionCallbackReceivesCompleteRequestOptions(t *testing.T) {
	const (
		authorityURI = "https://login.microsoftonline.com/runtime-tenant"
		claims       = `{"access_token":{"essential":true}}`
	)
	var got AssertionRequestOptions
	cred := NewCredFromAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (string, error) {
		got = opts
		return "opaque-assertion", nil
	})
	router := &bearerMtlsRouter{host: "login.microsoftonline.com", tenant: "runtime-tenant"}
	client, err := New(authorityURI, fakeClientID, cred,
		WithHTTPClient(router),
		WithInstanceDiscovery(false),
		WithClientCapabilities([]string{"CP1", "CP2"}),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("correlation ID is per request", func(t *testing.T) {
		var ids []string
		cred := NewCredFromAssertionCallback(func(_ context.Context, opts AssertionRequestOptions) (string, error) {
			ids = append(ids, opts.CorrelationID)
			return "opaque-assertion", nil
		})
		router := &bearerMtlsRouter{host: "login.microsoftonline.com", tenant: "tenant"}
		client, err := New("https://login.microsoftonline.com/tenant", fakeClientID, cred,
			WithHTTPClient(router),
			WithInstanceDiscovery(false),
		)
		if err != nil {
			t.Fatal(err)
		}
		for _, claims := range []string{`{"request":1}`, `{"request":2}`} {
			if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope, WithClaims(claims)); err != nil {
				t.Fatal(err)
			}
		}
		if len(ids) != 2 || ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
			t.Fatalf("callback correlation IDs = %v, want two distinct non-empty values", ids)
		}
		headers := router.tokenRequestHeaders()
		if len(headers) != 2 {
			t.Fatalf("token request count = %d, want 2", len(headers))
		}
		for i := range headers {
			if got := headers[i].Get("client-request-id"); got != ids[i] {
				t.Errorf("request %d client-request-id = %q, callback CorrelationID = %q", i, got, ids[i])
			}
		}
	})
	if _, err := client.AcquireTokenByCredential(context.Background(), tokenScope,
		WithClaims(claims), WithFMIPath("fmi/path")); err != nil {
		t.Fatal(err)
	}
	req := router.tokenRequest()
	if req == nil {
		t.Fatal("no token request was sent")
	}
	if got.ClientID != fakeClientID ||
		got.TokenEndpoint != req.String() ||
		got.TenantID != "runtime-tenant" ||
		got.Authority != authorityURI+"/" ||
		got.Claims != claims ||
		got.FMIPath != "fmi/path" ||
		got.CorrelationID == "" {
		t.Errorf("incomplete assertion options: %+v (request URI %q)", got, req)
	}
	if !reflect.DeepEqual(got.ClientCapabilities, []string{"CP1", "CP2"}) {
		t.Errorf("ClientCapabilities = %v, want [CP1 CP2]", got.ClientCapabilities)
	}
	if requestID := router.tokenRequestHeader().Get("client-request-id"); requestID != got.CorrelationID {
		t.Errorf("token request client-request-id = %q, callback CorrelationID = %q", requestID, got.CorrelationID)
	}
}

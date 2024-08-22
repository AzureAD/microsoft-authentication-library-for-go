// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
package managedidentity

import (
	"context"
	"testing"
)

func fakeClient(mangedIdentityId ID, options ...Option) (Client, error) {
	client, err := New(mangedIdentityId, options...)

	if err != nil {
		return Client{}, err
	}

	return client, nil
}

func TestManagedIdentity(t *testing.T) {
	client, err := fakeClient(SystemAssigned())

	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireToken(context.Background(), "scope", WithClaims("claim"))

	if err == nil {
		t.Errorf("TestManagedIdentity: unexpected nil error from TestManagedIdentity")
	}
}

func TestManagedIdentityWithClaims(t *testing.T) {
	client, err := fakeClient(ClientID("123"))

	if err != nil {
		t.Fatal(err)
	}

	_, err = client.AcquireToken(context.Background(), "scope", WithClaims("claim"))

	if err == nil {
		t.Errorf("TestManagedIdentityWithClaims: unexpected nil error from TestManagedIdentityWithClaims")
	}
}

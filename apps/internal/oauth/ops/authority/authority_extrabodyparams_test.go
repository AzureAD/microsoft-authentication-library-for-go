// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"testing"
)

func TestExtraBodyParametersHash(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]func(context.Context) (string, error)
		wantHash bool
	}{
		{
			name:     "nil params",
			params:   nil,
			wantHash: false,
		},
		{
			name:     "empty params",
			params:   map[string]func(context.Context) (string, error){},
			wantHash: false,
		},
		{
			name: "single param",
			params: map[string]func(context.Context) (string, error){
				"param1": func(ctx context.Context) (string, error) {
					return "value1", nil
				},
			},
			wantHash: true,
		},
		{
			name: "multiple params",
			params: map[string]func(context.Context) (string, error){
				"param1": func(ctx context.Context) (string, error) {
					return "value1", nil
				},
				"param2": func(ctx context.Context) (string, error) {
					return "value2", nil
				},
			},
			wantHash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := AuthParams{
				ExtraBodyParameters: tt.params,
			}
			hash := ap.ExtraBodyParametersHash()
			if tt.wantHash && hash == "" {
				t.Error("expected non-empty hash but got empty string")
			}
			if !tt.wantHash && hash != "" {
				t.Errorf("expected empty hash but got %q", hash)
			}
		})
	}
}

func TestExtraBodyParametersHashConsistency(t *testing.T) {
	// Test that the same parameters produce the same hash
	params1 := map[string]func(context.Context) (string, error){
		"param1": func(ctx context.Context) (string, error) {
			return "value1", nil
		},
		"param2": func(ctx context.Context) (string, error) {
			return "value2", nil
		},
	}

	params2 := map[string]func(context.Context) (string, error){
		"param1": func(ctx context.Context) (string, error) {
			return "value1", nil
		},
		"param2": func(ctx context.Context) (string, error) {
			return "value2", nil
		},
	}

	ap1 := AuthParams{ExtraBodyParameters: params1}
	ap2 := AuthParams{ExtraBodyParameters: params2}

	hash1 := ap1.ExtraBodyParametersHash()
	hash2 := ap2.ExtraBodyParametersHash()

	if hash1 != hash2 {
		t.Errorf("expected same hash for same parameter keys, got %q and %q", hash1, hash2)
	}
}

func TestExtraBodyParametersHashDifferentParams(t *testing.T) {
	// Test that different parameters produce different hashes
	params1 := map[string]func(context.Context) (string, error){
		"param1": func(ctx context.Context) (string, error) {
			return "value1", nil
		},
	}

	params2 := map[string]func(context.Context) (string, error){
		"param2": func(ctx context.Context) (string, error) {
			return "value2", nil
		},
	}

	ap1 := AuthParams{ExtraBodyParameters: params1}
	ap2 := AuthParams{ExtraBodyParameters: params2}

	hash1 := ap1.ExtraBodyParametersHash()
	hash2 := ap2.ExtraBodyParametersHash()

	if hash1 == hash2 {
		t.Errorf("expected different hashes for different parameter keys, both got %q", hash1)
	}
}

func TestAppKeyWithExtraBodyParameters(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		tenant   string
		params   map[string]func(context.Context) (string, error)
		wantDiff bool // whether cache key should differ from base key
	}{
		{
			name:     "no extra params",
			clientID: "client1",
			tenant:   "tenant1",
			params:   nil,
			wantDiff: false,
		},
		{
			name:     "with extra params",
			clientID: "client1",
			tenant:   "tenant1",
			params: map[string]func(context.Context) (string, error){
				"custom_param": func(ctx context.Context) (string, error) {
					return "value", nil
				},
			},
			wantDiff: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apBase := AuthParams{
				ClientID: tt.clientID,
				AuthorityInfo: Info{
					Tenant: tt.tenant,
				},
			}
			baseKey := apBase.AppKey()

			apWithParams := AuthParams{
				ClientID: tt.clientID,
				AuthorityInfo: Info{
					Tenant: tt.tenant,
				},
				ExtraBodyParameters: tt.params,
			}
			keyWithParams := apWithParams.AppKey()

			if tt.wantDiff && baseKey == keyWithParams {
				t.Error("expected different cache keys with extra params but got same")
			}
			if !tt.wantDiff && baseKey != keyWithParams {
				t.Errorf("expected same cache keys without extra params but got %q and %q", baseKey, keyWithParams)
			}
		})
	}
}

func TestAppKeyWithExtraBodyParametersUniqueness(t *testing.T) {
	// Test that different extra body parameters produce different cache keys
	clientID := "test_client"
	tenant := "test_tenant"

	params1 := map[string]func(context.Context) (string, error){
		"param1": func(ctx context.Context) (string, error) {
			return "value1", nil
		},
	}

	params2 := map[string]func(context.Context) (string, error){
		"param2": func(ctx context.Context) (string, error) {
			return "value2", nil
		},
	}

	ap1 := AuthParams{
		ClientID: clientID,
		AuthorityInfo: Info{
			Tenant: tenant,
		},
		ExtraBodyParameters: params1,
	}

	ap2 := AuthParams{
		ClientID: clientID,
		AuthorityInfo: Info{
			Tenant: tenant,
		},
		ExtraBodyParameters: params2,
	}

	key1 := ap1.AppKey()
	key2 := ap2.AppKey()

	if key1 == key2 {
		t.Errorf("expected different cache keys for different extra params, both got %q", key1)
	}
}

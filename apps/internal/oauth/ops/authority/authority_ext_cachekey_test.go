// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"strings"
	"testing"
)

func TestCacheExtKeyGenerator(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]string
		wantHash bool
	}{
		{
			name:     "nil params",
			params:   nil,
			wantHash: false,
		},
		{
			name:     "empty params",
			params:   map[string]string{},
			wantHash: false,
		},
		{
			name: "single param",
			params: map[string]string{
				"param1": "value1",
			},
			wantHash: true,
		},
		{
			name: "multiple params",
			params: map[string]string{
				"param1": "value1",
				"param2": "value2",
			},
			wantHash: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := AuthParams{
				CacheKeyComponents: tt.params,
			}
			hash := ap.CacheExtKeyGenerator()
			if tt.wantHash && hash == "" {
				t.Error("expected non-empty hash but got empty string")
			}
			if !tt.wantHash && hash != "" {
				t.Errorf("expected empty hash but got %q", hash)
			}
		})
	}
}

func TestCacheKeyComponentHashConsistency(t *testing.T) {
	// Test that the same parameters produce the same hash
	params1 := map[string]string{
		"param1": "value1",
		"param2": "value2",
	}

	params2 := map[string]string{
		"param1": "value1",
		"param2": "value2",
	}

	ap1 := AuthParams{CacheKeyComponents: params1}
	ap2 := AuthParams{CacheKeyComponents: params2}

	hash1 := ap1.CacheExtKeyGenerator()
	hash2 := ap2.CacheExtKeyGenerator()

	if hash1 != hash2 {
		t.Errorf("expected same hash for same parameter keys, got %q and %q", hash1, hash2)
	}
}

func TestCacheKeyComponentHashInConsistency(t *testing.T) {
	// Test that different parameters produce different hashes
	params1 := map[string]string{
		"param1": "value1",
	}

	params2 := map[string]string{
		"param2": "value2",
	}

	ap1 := AuthParams{CacheKeyComponents: params1}
	ap2 := AuthParams{CacheKeyComponents: params2}

	hash1 := ap1.CacheExtKeyGenerator()
	hash2 := ap2.CacheExtKeyGenerator()

	if hash1 == hash2 {
		t.Errorf("expected different hashes for different parameter keys, both got %q", hash1)
	}
}

func TestAppKeyWithCacheKeyComponent(t *testing.T) {
	tests := []struct {
		name                string
		clientID            string
		tenant              string
		params              map[string]string
		wantedExtraCacheKey string
	}{
		{
			name:                "no extra params",
			clientID:            "client1",
			tenant:              "tenant1",
			params:              nil,
			wantedExtraCacheKey: "",
		},
		{
			name:     "with extra params",
			clientID: "client1",
			tenant:   "tenant1",
			params: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			wantedExtraCacheKey: "bns2ytmx5hxkh4fnfixridmezpbbayhnmuh6t4bbghi",
		},
		{
			name:     "with extra params 2",
			clientID: "client1",
			tenant:   "tenant1",
			params: map[string]string{
				"key3": "value3",
				"key4": "value4",
			},
			wantedExtraCacheKey: "3-rg6_wyjx5bcy0c3cqq7gajtzgsqy3oxqpwj4y8k4u",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apWithParams := AuthParams{
				ClientID: tt.clientID,
				AuthorityInfo: Info{
					Tenant: tt.tenant,
				},
				CacheKeyComponents: tt.params,
			}
			keyWithParams := apWithParams.AppKey()
			if !strings.Contains(keyWithParams, tt.wantedExtraCacheKey) {
				t.Errorf("expected cache keys for params in app key not found but got %q and %q", tt.wantedExtraCacheKey, keyWithParams)
			}
		})
	}
}

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

// TestCacheKeyComponentHashNoBoundaryCollision guards against ambiguous component encoding. With a
// plain key+value concatenation (no separators) these two distinct component sets both render to
// "axbYbZ" (sorted keys "a","b"):
//
//	{"a":"xbY", "b":"Z"}  -> "a"+"xbY"+"b"+"Z"
//	{"a":"x",   "b":"YbZ"} -> "a"+"x"+"b"+"YbZ"
//
// so they would share a cache entry and could return the wrong token. The length-prefixed encoding
// must keep them distinct. This matters because client_claims is arbitrary caller JSON that can
// contain another component's key (e.g. "fmi_path") at a colliding boundary.
func TestCacheKeyComponentHashNoBoundaryCollision(t *testing.T) {
	ap1 := AuthParams{CacheKeyComponents: map[string]string{"a": "xbY", "b": "Z"}}
	ap2 := AuthParams{CacheKeyComponents: map[string]string{"a": "x", "b": "YbZ"}}

	if ap1.CacheExtKeyGenerator() == ap2.CacheExtKeyGenerator() {
		t.Error("distinct cache key components must not produce the same hash")
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
			wantedExtraCacheKey: "latlwkpewb_a0rcsmjvkecqt0_huumkw4sflzociike",
		},
		{
			name:     "with extra params 2",
			clientID: "client1",
			tenant:   "tenant1",
			params: map[string]string{
				"key3": "value3",
				"key4": "value4",
			},
			wantedExtraCacheKey: "jjoe9jgfmdtnj0rzuetsqy7kzs2m1xfnjjxwsfxsrxq",
		},
		{
			name:     "with extra 5 params",
			clientID: "client1",
			tenant:   "tenant1",
			params: map[string]string{
				"key3": "value3",
				"key4": "value4",
				"key5": "value5",
				"key6": "value6",
				"key7": "value7",
			},
			wantedExtraCacheKey: "prrdp31y37ufw3lo7hly0oimjjvg_34m9ji30ocu4tw",
		},
		{
			name:     "with extra 5 params different order ",
			clientID: "client1",
			tenant:   "tenant1",
			params: map[string]string{
				"key7": "value7",
				"key4": "value4",
				"key6": "value6",
				"key5": "value5",
				"key3": "value3",
			},
			wantedExtraCacheKey: "prrdp31y37ufw3lo7hly0oimjjvg_34m9ji30ocu4tw",
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

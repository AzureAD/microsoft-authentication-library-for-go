// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"net/url"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

func TestAddExtraBodyParameters(t *testing.T) {
	tests := []struct {
		name     string
		params   map[string]string
		validate func(*testing.T, url.Values)
	}{
		{
			name:   "nil params",
			params: nil,
			validate: func(t *testing.T, v url.Values) {
				// Should not add any parameters
				if len(v) > 0 {
					t.Errorf("expected no parameters to be added, got %d", len(v))
				}
			},
		},
		{
			name:   "empty params",
			params: map[string]string{},
			validate: func(t *testing.T, v url.Values) {
				// Should not add any parameters
				if len(v) > 0 {
					t.Errorf("expected no parameters to be added, got %d", len(v))
				}
			},
		},
		{
			name: "single parameter",
			params: map[string]string{
				"custom_param": "custom_value",
			},
			validate: func(t *testing.T, v url.Values) {

				if v.Get("custom_param") != "custom_value" {
					t.Errorf("expected custom_param=custom_value, got %s", v.Get("custom_param"))
				}
			},
		},
		{
			name: "multiple parameters",
			params: map[string]string{
				"param1": "value1",
				"param2": "value2",
				"param3": "value3",
			},
			validate: func(t *testing.T, v url.Values) {
				if v.Get("param1") != "value1" {
					t.Errorf("expected param1=value1, got %s", v.Get("param1"))
				}
				if v.Get("param2") != "value2" {
					t.Errorf("expected param2=value2, got %s", v.Get("param2"))
				}
				if v.Get("param3") != "value3" {
					t.Errorf("expected param3=value3, got %s", v.Get("param3"))
				}
			},
		},
		{
			name: "Empty value should not be passed",
			params: map[string]string{
				"param1": "",
				"param2": "",
			},
			validate: func(t *testing.T, v url.Values) {
				if v.Has("param1") {
					t.Errorf("param1 was found but should not be present")
				}
				if v.Has("param2") {
					t.Errorf("param2 was found but should not be present")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			v := url.Values{}
			ap := authority.AuthParams{
				ExtraBodyParameters: tt.params,
			}
			err := addExtraBodyParameters(ctx, v, ap)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.validate != nil {
				tt.validate(t, v)
			}
		})
	}
}

func TestAddExtraBodyParametersDoesNotOverwrite(t *testing.T) {
	// Test that extra body parameters are added without overwriting existing parameters
	v := url.Values{}
	v.Set("existing_param", "existing_value")

	params := map[string]string{
		"new_param": "new_value",
	}

	ap := authority.AuthParams{
		ExtraBodyParameters: params,
	}

	err := addExtraBodyParameters(context.Background(), v, ap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that existing parameter is still there
	if v.Get("existing_param") != "existing_value" {
		t.Errorf("existing parameter was modified or removed")
	}

	// Check that new parameter was added
	if v.Get("new_param") != "new_value" {
		t.Errorf("new parameter was not added correctly")
	}
}

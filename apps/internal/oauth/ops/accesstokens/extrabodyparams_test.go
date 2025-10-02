// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package accesstokens

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

func TestAddExtraBodyParameters(t *testing.T) {
	tests := []struct {
		name        string
		params      map[string]func(context.Context) (string, error)
		expectError bool
		validate    func(*testing.T, url.Values)
	}{
		{
			name:        "nil params",
			params:      nil,
			expectError: false,
			validate: func(t *testing.T, v url.Values) {
				// Should not add any parameters
				if len(v) > 0 {
					t.Errorf("expected no parameters to be added, got %d", len(v))
				}
			},
		},
		{
			name:        "empty params",
			params:      map[string]func(context.Context) (string, error){},
			expectError: false,
			validate: func(t *testing.T, v url.Values) {
				// Should not add any parameters
				if len(v) > 0 {
					t.Errorf("expected no parameters to be added, got %d", len(v))
				}
			},
		},
		{
			name: "single parameter",
			params: map[string]func(context.Context) (string, error){
				"custom_param": func(ctx context.Context) (string, error) {
					return "custom_value", nil
				},
			},
			expectError: false,
			validate: func(t *testing.T, v url.Values) {
				if v.Get("custom_param") != "custom_value" {
					t.Errorf("expected custom_param=custom_value, got %s", v.Get("custom_param"))
				}
			},
		},
		{
			name: "multiple parameters",
			params: map[string]func(context.Context) (string, error){
				"param1": func(ctx context.Context) (string, error) {
					return "value1", nil
				},
				"param2": func(ctx context.Context) (string, error) {
					return "value2", nil
				},
				"param3": func(ctx context.Context) (string, error) {
					return "value3", nil
				},
			},
			expectError: false,
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
			name: "parameter with error",
			params: map[string]func(context.Context) (string, error){
				"failing_param": func(ctx context.Context) (string, error) {
					return "", errors.New("intentional error")
				},
			},
			expectError: true,
		},
		{
			name: "mixed parameters with one error",
			params: map[string]func(context.Context) (string, error){
				"good_param": func(ctx context.Context) (string, error) {
					return "good_value", nil
				},
				"bad_param": func(ctx context.Context) (string, error) {
					return "", errors.New("intentional error")
				},
			},
			expectError: true,
		},
		{
			name: "parameter with special characters",
			params: map[string]func(context.Context) (string, error){
				"special_param": func(ctx context.Context) (string, error) {
					return "value with spaces & special=chars", nil
				},
			},
			expectError: false,
			validate: func(t *testing.T, v url.Values) {
				expected := "value with spaces & special=chars"
				if v.Get("special_param") != expected {
					t.Errorf("expected special_param=%s, got %s", expected, v.Get("special_param"))
				}
			},
		},
		{
			name: "nil parameter function",
			params: map[string]func(context.Context) (string, error){
				"nil_func": nil,
			},
			expectError: false,
			validate: func(t *testing.T, v url.Values) {
				// Nil function should be skipped
				if v.Has("nil_func") {
					t.Error("nil function should not add parameter")
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

			if tt.expectError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, v)
				}
			}
		})
	}
}

func TestAddExtraBodyParametersContextPropagation(t *testing.T) {
	// Test that context is properly passed to parameter functions
	type contextKey string
	key := contextKey("test_key")
	expectedValue := "test_value"
	ctx := context.WithValue(context.Background(), key, expectedValue)

	contextReceived := false
	params := map[string]func(context.Context) (string, error){
		"param_from_context": func(ctx context.Context) (string, error) {
			contextReceived = true
			val := ctx.Value(key)
			if val == nil {
				return "", errors.New("context value not found")
			}
			return val.(string), nil
		},
	}

	v := url.Values{}
	ap := authority.AuthParams{
		ExtraBodyParameters: params,
	}

	err := addExtraBodyParameters(ctx, v, ap)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !contextReceived {
		t.Error("parameter function was not called with context")
	}

	if v.Get("param_from_context") != expectedValue {
		t.Errorf("expected param_from_context=%s, got %s", expectedValue, v.Get("param_from_context"))
	}
}

func TestAddExtraBodyParametersEvaluation(t *testing.T) {
	// Test that parameter functions are evaluated each time
	callCount := 0
	params := map[string]func(context.Context) (string, error){
		"counter": func(ctx context.Context) (string, error) {
			callCount++
			return "called", nil
		},
	}

	ap := authority.AuthParams{
		ExtraBodyParameters: params,
	}

	// First call
	v1 := url.Values{}
	err := addExtraBodyParameters(context.Background(), v1, ap)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected function to be called once, was called %d times", callCount)
	}

	// Second call - function should be evaluated again
	v2 := url.Values{}
	err = addExtraBodyParameters(context.Background(), v2, ap)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if callCount != 2 {
		t.Errorf("expected function to be called twice total, was called %d times", callCount)
	}
}

func TestAddExtraBodyParametersDoesNotOverwrite(t *testing.T) {
	// Test that extra body parameters are added without overwriting existing parameters
	v := url.Values{}
	v.Set("existing_param", "existing_value")

	params := map[string]func(context.Context) (string, error){
		"new_param": func(ctx context.Context) (string, error) {
			return "new_value", nil
		},
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

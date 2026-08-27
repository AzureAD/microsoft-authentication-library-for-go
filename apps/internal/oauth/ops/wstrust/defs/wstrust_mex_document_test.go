// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package defs

import "testing"

func TestUpdateEndpoint(t *testing.T) {
	testCases := []struct {
		name   string
		cached Endpoint
		found  Endpoint
		want   Endpoint
	}{
		{
			name:   "selects first endpoint",
			cached: Endpoint{},
			found:  Endpoint{Version: Trust2005, URL: "https://2005.example"},
			want:   Endpoint{Version: Trust2005, URL: "https://2005.example"},
		},
		{
			name:   "upgrades from WS-Trust 2005 to 1.3",
			cached: Endpoint{Version: Trust2005, URL: "https://2005.example"},
			found:  Endpoint{Version: Trust13, URL: "https://13.example"},
			want:   Endpoint{Version: Trust13, URL: "https://13.example"},
		},
		{
			name:   "retains WS-Trust 1.3 over 2005",
			cached: Endpoint{Version: Trust13, URL: "https://13.example"},
			found:  Endpoint{Version: Trust2005, URL: "https://2005.example"},
			want:   Endpoint{Version: Trust13, URL: "https://13.example"},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := updateEndpoint(testCase.cached, testCase.found); got != testCase.want {
				t.Errorf("updateEndpoint(%+v, %+v) = %+v, want %+v", testCase.cached, testCase.found, got, testCase.want)
			}
		})
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"os"
	"testing"
)

// TestInfoResolveRegion covers the sentinel replacement that keeps a successfully auto-detected
// region from being thrown away. Before this, detection happened inside AADInstanceDiscovery against
// a by-value copy of Info, so the caller's AuthParams kept the "TryAutoDetect" sentinel and
// MtlsTokenEndpoint fell back to the global mTLS host.
func TestInfoResolveRegion(t *testing.T) {
	const detected = "centralus"
	for _, test := range []struct {
		desc   string
		region string
		env    string
		want   string
	}{
		{desc: "sentinel is replaced by the detected region", region: autoDetectRegion, env: detected, want: detected},
		{desc: "sentinel with no detection resolves to empty", region: autoDetectRegion, env: "", want: ""},
		{desc: "explicit region is left alone", region: "westus", env: detected, want: "westus"},
		{desc: "unset region is left alone", region: "", env: detected, want: ""},
	} {
		t.Run(test.desc, func(t *testing.T) {
			resetDetectedRegion()
			defer resetDetectedRegion()
			if test.env != "" {
				if err := os.Setenv(regionName, test.env); err != nil {
					t.Fatal(err)
				}
				defer os.Unsetenv(regionName)
			}

			info := Info{Host: "login.microsoftonline.com", Tenant: "contoso", Region: test.region}
			// A canceled context keeps the no-detection case from probing IMDS on a machine that
			// happens to answer.
			ctx := context.Background()
			if test.env == "" {
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = canceled
			}
			info.ResolveRegion(ctx)
			if info.Region != test.want {
				t.Fatalf("Region = %q, want %q", info.Region, test.want)
			}

			// Resolution must be idempotent: a second pass can't overwrite what the first produced.
			info.ResolveRegion(ctx)
			if info.Region != test.want {
				t.Fatalf("Region after a second resolve = %q, want %q", info.Region, test.want)
			}
		})
	}
}

// TestDetectRegionEnvironmentIsNotMemoized pins that the memoization added to keep auto-detection
// from re-probing IMDS on every acquisition never caches the environment variable, which a process
// may set or change at any point.
func TestDetectRegionEnvironmentIsNotMemoized(t *testing.T) {
	resetDetectedRegion()
	defer resetDetectedRegion()

	if err := os.Setenv(regionName, "eastus"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(regionName)
	if got := detectRegion(context.Background()); got != "eastus" {
		t.Fatalf("detectRegion = %q, want eastus", got)
	}
	if err := os.Setenv(regionName, "WEST US 2"); err != nil {
		t.Fatal(err)
	}
	// Spaces are stripped and the value is lowercased, as region names are short-form.
	if got := detectRegion(context.Background()); got != "westus2" {
		t.Fatalf("detectRegion after the environment changed = %q, want westus2", got)
	}
}

// TestDetectRegionMemoizesDetection pins the memoization itself: a failed probe is remembered so
// repeated acquisitions don't pay for it again, but a failure caused only by the caller's canceled
// context is not, since a later request with a live context should still get a chance.
func TestDetectRegionMemoizesDetection(t *testing.T) {
	if err := os.Unsetenv(regionName); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	resetDetectedRegion()
	defer resetDetectedRegion()
	if got := detectRegion(canceled); got != "" {
		t.Fatalf("detectRegion with a canceled context = %q, want empty", got)
	}
	detectedRegionMu.Lock()
	known := detectedRegionKnown
	detectedRegionMu.Unlock()
	if known {
		t.Error("a failure caused by the caller's canceled context was memoized")
	}

	// A detection that ran to completion is remembered, so the probe isn't repeated.
	resetDetectedRegion()
	if err := os.Setenv(regionName, "northeurope"); err != nil {
		t.Fatal(err)
	}
	defer os.Unsetenv(regionName)
	info := Info{Region: autoDetectRegion}
	info.ResolveRegion(context.Background())
	if info.Region != "northeurope" {
		t.Fatalf("Region = %q, want northeurope", info.Region)
	}
}

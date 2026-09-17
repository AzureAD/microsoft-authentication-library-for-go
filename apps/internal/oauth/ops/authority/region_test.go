// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
				t.Setenv(regionName, test.env)
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

	t.Setenv(regionName, "eastus")
	if got := detectRegion(context.Background()); got != "eastus" {
		t.Fatalf("detectRegion = %q, want eastus", got)
	}
	// A second, equally valid region. The change has to be visible on the very next call, which is
	// only possible if the environment is re-read rather than remembered from the first one.
	t.Setenv(regionName, "westus2")
	if got := detectRegion(context.Background()); got != "westus2" {
		t.Fatalf("detectRegion after the environment changed = %q, want westus2", got)
	}
}

// TestDetectRegionBlankEnvironmentResolvesToNothing pins the seam that lets higher layers exercise
// "a region was asked for and none was found" deterministically. REGION_NAME is consulted before
// IMDS, and a value that is set but is not a valid Azure region name is rejected outright rather
// than normalized, so a blank value resolves to no region without a network probe - and without
// memoizing anything, since the environment is deliberately re-read every time.
// confidential.TestRegionAutoDetectFailureFollowsTheNoRegionPath relies on both halves of that.
func TestDetectRegionBlankEnvironmentResolvesToNothing(t *testing.T) {
	resetDetectedRegion()
	defer resetDetectedRegion()

	t.Setenv(regionName, "   ")

	if got := detectRegion(context.Background()); got != "" {
		t.Fatalf("detectRegion with a blank REGION_NAME = %q, want empty", got)
	}
	// Nothing was memoized, which is only possible if the environment short-circuited before the
	// IMDS probe. If this ever starts failing, the blank value is reaching the network and the
	// higher-level test that depends on this seam is no longer deterministic.
	detectedRegionMu.Lock()
	known := detectedRegionKnown
	detectedRegionMu.Unlock()
	if known {
		t.Error("a blank REGION_NAME reached the IMDS probe instead of short-circuiting")
	}

	info := Info{Host: "login.microsoftonline.com", Tenant: "contoso", Region: autoDetectRegion}
	info.ResolveRegion(context.Background())
	if info.Region != "" {
		t.Fatalf("Region = %q, want empty so the flow takes the no-region path", info.Region)
	}
}

// TestDetectRegionMemoizesDetection pins the memoization itself: a failed probe is remembered so
// repeated acquisitions don't pay for it again, but a failure caused only by the caller's canceled
// context is not, since a later request with a live context should still get a chance.
func TestDetectRegionMemoizesDetection(t *testing.T) {
	if err := os.Unsetenv(regionName); err != nil {
		t.Fatal(err)
	}

	t.Run("single flight and cache", func(t *testing.T) {
		t.Setenv(regionName, "")
		resetDetectedRegion()
		defer resetDetectedRegion()
		originalProbe := probeRegion
		defer func() { probeRegion = originalProbe }()

		started := make(chan struct{})
		release := make(chan struct{})
		var calls int32
		probeRegion = func(context.Context) string {
			if atomic.AddInt32(&calls, 1) == 1 {
				close(started)
			}
			<-release
			return "eastus2"
		}

		const waiters = 12
		results := make(chan string, waiters)
		var wg sync.WaitGroup
		for i := 0; i < waiters; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results <- detectRegion(context.Background())
			}()
		}
		<-started
		close(release)
		wg.Wait()
		close(results)
		for region := range results {
			if region != "eastus2" {
				t.Errorf("detectRegion = %q, want eastus2", region)
			}
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("IMDS probe ran %d times, want 1", got)
		}
		if got := detectRegion(context.Background()); got != "eastus2" {
			t.Fatalf("cached detectRegion = %q, want eastus2", got)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("cached lookup started another probe; calls = %d", got)
		}
	})

	t.Run("canceled waiter does not cancel probe", func(t *testing.T) {
		t.Setenv(regionName, "")
		resetDetectedRegion()
		defer resetDetectedRegion()
		originalProbe := probeRegion
		defer func() { probeRegion = originalProbe }()

		started := make(chan struct{})
		release := make(chan struct{})
		probeRegion = func(context.Context) string {
			close(started)
			<-release
			return "centralus"
		}
		active := make(chan string, 1)
		go func() { active <- detectRegion(context.Background()) }()
		<-started

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		begin := time.Now()
		if got := detectRegion(ctx); got != "" {
			t.Fatalf("canceled waiter got %q, want empty", got)
		}
		if elapsed := time.Since(begin); elapsed > 100*time.Millisecond {
			t.Fatalf("canceled waiter took %s to return", elapsed)
		}

		close(release)
		if got := <-active; got != "centralus" {
			t.Fatalf("active probe returned %q, want centralus", got)
		}
		if got := detectRegion(context.Background()); got != "centralus" {
			t.Fatalf("probe result wasn't cached: %q", got)
		}
	})

	t.Run("failure and retry semantics", func(t *testing.T) {
		t.Setenv(regionName, "")
		resetDetectedRegion()
		defer resetDetectedRegion()
		originalProbe := probeRegion
		defer func() { probeRegion = originalProbe }()

		var calls int32
		probeRegion = func(context.Context) string {
			atomic.AddInt32(&calls, 1)
			return ""
		}
		if got := detectRegion(context.Background()); got != "" {
			t.Fatalf("failed probe returned %q", got)
		}
		if got := detectRegion(context.Background()); got != "" {
			t.Fatalf("cached failed probe returned %q", got)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("completed failure was probed %d times, want 1", got)
		}

		resetDetectedRegion()
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		if got := detectRegion(canceled); got != "" {
			t.Fatalf("pre-canceled lookup returned %q", got)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("pre-canceled lookup started a probe; calls = %d", got)
		}
		probeRegion = func(context.Context) string {
			atomic.AddInt32(&calls, 1)
			return "westus2"
		}
		if got := detectRegion(context.Background()); got != "westus2" {
			t.Fatalf("live retry returned %q, want westus2", got)
		}
		if got := atomic.LoadInt32(&calls); got != 2 {
			t.Fatalf("live retry probe count = %d, want 2 total", got)
		}
	})
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
	t.Setenv(regionName, "northeurope")
	info := Info{Region: autoDetectRegion}
	info.ResolveRegion(context.Background())
	if info.Region != "northeurope" {
		t.Fatalf("Region = %q, want northeurope", info.Region)
	}
}

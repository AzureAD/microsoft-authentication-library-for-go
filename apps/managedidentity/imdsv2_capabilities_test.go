// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
)

// authParamsForTest returns parameters carrying no cache components, so a test
// can observe exactly what stamping adds.
func authParamsForTest() authority.AuthParams {
	return authority.AuthParams{ClientID: "client", Scopes: []string{"https://vault.azure.net"}}
}

// The numbering is a contract with MSAL .NET, not an implementation detail: the
// two libraries describe the same host to the same callers, and the gap at 2 is
// reserved for a tier neither of them defines yet.
func TestMtlsBindingStrengthValues(t *testing.T) {
	for _, test := range []struct {
		strength MtlsBindingStrength
		value    int
		name     string
	}{
		{MtlsBindingStrengthNone, 0, "None"},
		{MtlsBindingStrengthSoftware, 1, "Software"},
		{MtlsBindingStrengthKeyGuard, 3, "KeyGuard"},
	} {
		if int(test.strength) != test.value {
			t.Fatalf("%s = %d, want %d", test.name, int(test.strength), test.value)
		}
		if test.strength.String() != test.name {
			t.Fatalf("String() = %q, want %q", test.strength.String(), test.name)
		}
	}
	if MtlsBindingStrengthSoftware >= MtlsBindingStrengthKeyGuard {
		t.Fatal("the tiers must order weakest to strongest, or a floor comparison is meaningless")
	}
}

// A host that answers the CSR metadata call speaks the key-bound protocol, and
// a VBS key is what raises it from the software floor to the attested tier.
func TestCapabilitiesReportsKeyGuardOnAttestableHost(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.Source != DefaultToIMDS {
		t.Fatalf("Source = %q, want %q", capabilities.Source, DefaultToIMDS)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("strength = %s, want KeyGuard", capabilities.MaxSupportedBindingStrength)
	}
	if !capabilities.IsMtlsPoPSupportedByHost() {
		t.Fatal("a host that can produce a KeyGuard key supports PoP")
	}
	if capabilities.ErrorReason != "" {
		t.Fatalf("ErrorReason = %q, want empty on a detected host", capabilities.ErrorReason)
	}
}

// A key that cannot be provisioned right now is a local condition. The host has
// already proved it speaks v2, so reporting None would tell a credential chain
// to abandon managed identity over something transient.
func TestCapabilitiesKeepsSoftwareFloorWhenKeyProviderFails(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	provider.err = errors.New("no VBS on this host")

	client := fake.newTestClient(t, SystemAssigned(), provider)
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
		t.Fatalf("strength = %s, want Software", capabilities.MaxSupportedBindingStrength)
	}
}

// A host that does not answer the CSR metadata call cannot bind anything, and
// the reason it gave is worth keeping: it is what a caller has to act on.
func TestCapabilitiesReportsNoneWhenMetadataUnavailable(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = 404
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
		t.Fatalf("strength = %s, want None", capabilities.MaxSupportedBindingStrength)
	}
	if capabilities.IsMtlsPoPSupportedByHost() {
		t.Fatal("a host with no v2 endpoint does not support PoP")
	}
	if capabilities.ErrorReason == "" {
		t.Fatal("the reason discovery failed should be reported, it is what a caller acts on")
	}
}

// Discovery probes the metadata service and provisions a key. Neither changes
// while the process runs, so a service resolving credentials on many goroutines
// must not pay for it repeatedly.
func TestCapabilitiesIsDiscoveredOnce(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.Capabilities(context.Background()); err != nil {
		t.Fatalf("first Capabilities: %v", err)
	}
	probes := fake.countOf("metadata")
	for i := 0; i < 5; i++ {
		if _, err := client.Capabilities(context.Background()); err != nil {
			t.Fatalf("Capabilities: %v", err)
		}
	}
	if fake.countOf("metadata") != probes {
		t.Fatalf("probed %d times, want %d: discovery should be cached for the process", fake.countOf("metadata"), probes)
	}
}

// A cancelled call must not publish its result, or one cancellation would be
// remembered as the host's answer for the rest of the process.
func TestCapabilitiesDoesNotCacheCancelledResult(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	client := fake.newTestClient(t, SystemAssigned(), provider)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Capabilities(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Capabilities on a cancelled context = %v, want context.Canceled", err)
	}

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities after cancellation: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("strength = %s, want KeyGuard: the cancelled call must not have been cached",
			capabilities.MaxSupportedBindingStrength)
	}
}

// A floor the host meets is invisible; the acquisition proceeds normally.
func TestMinStrengthAllowsHostThatMeetsIt(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(MtlsBindingStrengthKeyGuard)); err != nil {
		t.Fatalf("AcquireToken under a floor the host meets: %v", err)
	}
}

// A floor the host cannot meet fails before IMDS is asked for a credential the
// caller would have refused.
func TestMinStrengthRejectsHostBelowFloor(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()
	provider.typ = keyTypeSoftware

	client := fake.newTestClient(t, SystemAssigned(), provider)
	fake.resetCalls()
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(MtlsBindingStrengthKeyGuard))
	if !errors.Is(err, ErrMinStrengthNotMet) {
		t.Fatalf("AcquireToken = %v, want ErrMinStrengthNotMet", err)
	}
	if !strings.Contains(err.Error(), "Software") || !strings.Contains(err.Error(), "KeyGuard") {
		t.Fatalf("error %q should name both what the host offers and what was required", err)
	}
	if fake.countOf("issue") != 0 {
		t.Fatal("a credential was requested for an acquisition that could never have succeeded")
	}
}

// No floor means no discovery: a caller who never asked for one must not pay
// for a probe.
func TestMinStrengthNoneSkipsDiscovery(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithMtlsPoPMinStrength(MtlsBindingStrengthNone)); err != nil {
		t.Fatalf("AcquireToken: %v", err)
	}
	capabilitiesCache.mu.Lock()
	cached := capabilitiesCache.result
	capabilitiesCache.mu.Unlock()
	if cached != nil {
		t.Fatal("discovery ran for a request that imposed no floor")
	}
}

// A floor is a statement about the key a token is bound to, so it cannot be
// honoured by a request that binds none.
func TestMinStrengthRequiresMtls(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	_, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsPoPMinStrength(MtlsBindingStrengthKeyGuard))
	if !errors.Is(err, ErrMinStrengthRequiresMtls) {
		t.Fatalf("AcquireToken = %v, want ErrMinStrengthRequiresMtls", err)
	}
}

// A token acquired under a floor was checked against a guarantee one acquired
// without a floor was not, so raising the floor must not be satisfiable by a
// token cached before it was set.
func TestCacheComponentsPartitionByMinStrength(t *testing.T) {
	base := authParamsForTest()
	AcquireTokenOptions{}.stampCacheComponents(&base)
	none := base.CacheExtKeyGenerator()

	floored := authParamsForTest()
	AcquireTokenOptions{minStrength: MtlsBindingStrengthKeyGuard}.stampCacheComponents(&floored)
	if floored.CacheExtKeyGenerator() == none {
		t.Fatal("a floored request shares a cache entry with an unfloored one")
	}

	software := authParamsForTest()
	AcquireTokenOptions{minStrength: MtlsBindingStrengthSoftware}.stampCacheComponents(&software)
	if software.CacheExtKeyGenerator() == floored.CacheExtKeyGenerator() {
		t.Fatal("two different floors share a cache entry")
	}
}

// Requesting no floor must leave the key exactly as it was before the option
// existed, or every token cached by an earlier version is orphaned.
func TestCacheComponentsUnchangedWithoutOptions(t *testing.T) {
	params := authParamsForTest()
	AcquireTokenOptions{}.stampCacheComponents(&params)
	if got := params.CacheExtKeyGenerator(); got != "" {
		t.Fatalf("CacheExtKeyGenerator = %q, want empty: a plain request must keep the legacy key shape", got)
	}
}

// A bearer token obtained over mTLS is issued under a different policy than one
// obtained over plain HTTP, so the two must not share an entry.
func TestCacheComponentsPartitionBearerOverMtls(t *testing.T) {
	plain := authParamsForTest()
	AcquireTokenOptions{}.stampCacheComponents(&plain)

	overMtls := authParamsForTest()
	AcquireTokenOptions{overMtls: true}.stampCacheComponents(&overMtls)
	if overMtls.CacheExtKeyGenerator() == plain.CacheExtKeyGenerator() {
		t.Fatal("a bearer token acquired over mTLS shares a cache entry with an ordinary one")
	}
}

// A token bound to an attested key carries a guarantee a token bound to an
// unattested key does not, so the two must not share an entry.
//
// The mTLS-bearer case is the one that has nothing else to fall back on: those
// are ordinary bearer tokens, so the authentication scheme contributes no key
// ID and the cache key components are the only thing separating them. The PoP
// case is additionally separated by the binding certificate's thumbprint, but
// it is partitioned here too because MSAL .NET stamps mi_att and a cache shared
// between the two libraries has to agree on the key.
func TestCacheComponentsPartitionByAttestation(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts AcquireTokenOptions
	}{
		{"mtls-bearer", AcquireTokenOptions{overMtls: true}},
		{"mtls-pop", AcquireTokenOptions{mtlsPoP: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			off := authParamsForTest()
			tc.opts.stampCacheComponents(&off)

			attested := tc.opts
			attested.attestation = true
			on := authParamsForTest()
			attested.stampCacheComponents(&on)

			if off.CacheExtKeyGenerator() == on.CacheExtKeyGenerator() {
				t.Fatal("an attested token shares a cache entry with an unattested one, " +
					"so a caller who asked for attestation can be served a token minted without it")
			}
		})
	}
}

// The component values are MSAL .NET's, so a cache shared with .NET partitions
// the same way. Pinning them keeps a refactor from silently diverging: the two
// libraries would still each partition correctly, but they would stop agreeing.
func TestCacheComponentValuesMatchDotNet(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts AcquireTokenOptions
		want map[string]string
	}{
		{"pop unattested", AcquireTokenOptions{mtlsPoP: true}, map[string]string{"mi_att": "0"}},
		{"pop attested", AcquireTokenOptions{mtlsPoP: true, attestation: true}, map[string]string{"mi_att": "1"}},
		{"bearer unattested", AcquireTokenOptions{overMtls: true}, map[string]string{"mtls_bearer": "0"}},
		{"bearer attested", AcquireTokenOptions{overMtls: true, attestation: true}, map[string]string{"mtls_bearer": "1"}},
		{
			// .NET stamps MtlsBindingStrength.ToString(), and a C# enum renders
			// as its member name, so this is "KeyGuard" and not "3".
			name: "floor is named, not numbered",
			opts: AcquireTokenOptions{mtlsPoP: true, minStrength: MtlsBindingStrengthKeyGuard},
			want: map[string]string{"mi_att": "0", "mi_minstrength": "KeyGuard"},
		},
		{
			name: "software floor",
			opts: AcquireTokenOptions{mtlsPoP: true, minStrength: MtlsBindingStrengthSoftware},
			want: map[string]string{"mi_att": "0", "mi_minstrength": "Software"},
		},
		// A plain request has to keep the key shape it had before any of these
		// options existed, or every token cached by an earlier version is lost.
		{"plain", AcquireTokenOptions{}, map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := authParamsForTest()
			tc.opts.stampCacheComponents(&params)
			if len(params.CacheKeyComponents) != len(tc.want) {
				t.Fatalf("components = %v, want %v", params.CacheKeyComponents, tc.want)
			}
			for k, want := range tc.want {
				if got := params.CacheKeyComponents[k]; got != want {
					t.Errorf("component %q = %q, want %q", k, got, want)
				}
			}
		})
	}
}

// Stamping runs on every acquisition against the same params, so an option that
// is no longer set has to be removed rather than left behind.
func TestCacheComponentsClearedWhenOptionsDropped(t *testing.T) {
	params := authParamsForTest()
	AcquireTokenOptions{overMtls: true, minStrength: MtlsBindingStrengthKeyGuard}.stampCacheComponents(&params)
	if len(params.CacheKeyComponents) != 2 {
		t.Fatalf("components = %v, want both recorded", params.CacheKeyComponents)
	}
	AcquireTokenOptions{}.stampCacheComponents(&params)
	if len(params.CacheKeyComponents) != 0 {
		t.Fatalf("components = %v, want empty once the options are dropped", params.CacheKeyComponents)
	}
}

// A cached token is normally served without contacting the service. Force
// refresh is what a caller reaches for when something outside this library has
// changed what the token should contain.
func TestForceRefreshBypassesTokenCache(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	served := fake.countOf("token")

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("second AcquireToken: %v", err)
	}
	if fake.countOf("token") != served {
		t.Fatalf("token requests = %d, want %d: the second call should have been served from the cache", fake.countOf("token"), served)
	}

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithForceRefresh()); err != nil {
		t.Fatalf("forced AcquireToken: %v", err)
	}
	if fake.countOf("token") != served+1 {
		t.Fatalf("token requests = %d, want %d: a forced refresh must reach the service", fake.countOf("token"), served+1)
	}
}

// The certificate identifies the machine and is unaffected by a token going
// stale. Re-minting one per forced call would be throttled by IMDS.
func TestForceRefreshKeepsBindingCertificate(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	provider := newFakeKeyProvider()

	client := fake.newTestClient(t, SystemAssigned(), provider)
	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession()); err != nil {
		t.Fatalf("first AcquireToken: %v", err)
	}
	issued := fake.countOf("issue")

	if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net",
		WithMtlsProofOfPossession(), WithForceRefresh()); err != nil {
		t.Fatalf("forced AcquireToken: %v", err)
	}
	if fake.countOf("issue") != issued {
		t.Fatalf("credential requests = %d, want %d: a forced token refresh must not re-mint the certificate",
			fake.countOf("issue"), issued)
	}
}

// Capability discovery uses a different retry policy from an acquisition, as
// MSAL .NET does with HttpRetryConditions.ImdsProbe. A 404 answers the question
// the probe is asking, so it is believed immediately: retrying cannot turn a
// v1-only host into a v2 host, and the backoff would be charged to every caller
// on such a host. TestIMDSv2RetriesA404BeforeReportingAV1OnlyHost pins the
// opposite behavior for the acquisition path, which contradicts the caller and
// so is worth re-checking.
func TestCapabilitiesDoesNotRetryA404Probe(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
		t.Fatalf("strength = %s, want None", capabilities.MaxSupportedBindingStrength)
	}
	if got := fake.countOf("metadata"); got != 1 {
		t.Fatalf("probe requests = %d, want one: a 404 says this host has no v2 endpoint", got)
	}
}

// A v1-only host still reports the binding strength its platform can reach, as
// MSAL .NET does in DetermineImdsV1BindingStrengthAsync: it reads the instance
// compute document and reports Software for a Windows VM whose security profile
// is Trusted Launch or Confidential. Reporting None here would make the two
// libraries disagree about the same machine.
func TestCapabilitiesReportsSoftwareStrengthOnAV1OnlyWindowsHost(t *testing.T) {
	for _, securityType := range []string{"TrustedLaunch", "confidentialvm"} {
		t.Run(securityType, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.metadataStatus = http.StatusNotFound
			fake.computeBody = `{"osType":"Windows","securityProfile":{"securityType":"` + securityType + `"}}`
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			capabilities, err := client.Capabilities(context.Background())
			if err != nil {
				t.Fatalf("Capabilities: %v", err)
			}
			if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
				t.Fatalf("strength = %s, want Software", capabilities.MaxSupportedBindingStrength)
			}
			if capabilities.Source != DefaultToIMDS {
				t.Fatalf("source = %s, want %s", capabilities.Source, DefaultToIMDS)
			}
			// The host was described successfully, so there is nothing to report.
			if capabilities.ErrorReason != "" {
				t.Fatalf("ErrorReason = %q, want empty", capabilities.ErrorReason)
			}
			if fake.countOf("compute") == 0 {
				t.Fatal("the compute document was never read")
			}
		})
	}
}

// A security profile that cannot bind reports None, and a Linux host reports
// None whatever its security type. MSAL .NET requires both conditions in
// ComputeMetadataResponse.IsMtlsPopSupported, so a test that only varied one of
// them would pass with either check missing.
func TestCapabilitiesReportsNoStrengthForAV1OnlyHostThatCannotBind(t *testing.T) {
	for name, body := range map[string]string{
		"linux trusted launch": `{"osType":"Linux","securityProfile":{"securityType":"TrustedLaunch"}}`,
		"windows standard":     `{"osType":"Windows","securityProfile":{"securityType":"Standard"}}`,
		"windows no profile":   `{"osType":"Windows"}`,
	} {
		t.Run(name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			fake.metadataStatus = http.StatusNotFound
			fake.computeBody = body
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

			capabilities, err := client.Capabilities(context.Background())
			if err != nil {
				t.Fatalf("Capabilities: %v", err)
			}
			if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
				t.Fatalf("strength = %s, want None", capabilities.MaxSupportedBindingStrength)
			}
			if capabilities.ErrorReason == "" {
				t.Fatal("ErrorReason is empty: a host that cannot bind has to say why")
			}
		})
	}
}

// Narrowing the probe policy must not turn it into no policy. A 500 is still a
// transient failure that says nothing about whether the host serves v2, so the
// probe retries it exactly as an acquisition would, and then asks the IMDSv1
// question the way MSAL .NET does after any v2 probe failure.
func TestCapabilitiesRetriesATransientProbeFailure(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusInternalServerError
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	probes := 0
	for _, call := range fake.calls {
		if call != "metadata" {
			break
		}
		probes++
	}
	if probes != 4 {
		t.Fatalf("calls = %q, want a 500 retried three times before anything else", strings.Join(fake.calls, ","))
	}
	// .NET falls through to the v1 probe on any v2 failure, not only on a 404
	// (ManagedIdentityClient.GetManagedIdentitySourceAsync).
	if len(fake.calls) == probes {
		t.Fatalf("calls = %q, want the v1 question asked after the v2 probe failed", strings.Join(fake.calls, ","))
	}
}

// The probe's contract is the inverse of an acquisition's: it omits the
// Metadata header precisely so a host that serves IMDSv2 rejects it, and that
// rejection is the proof. MSAL .NET's probe is written the same way
// (ImdsManagedIdentitySource.ProbeImdsEndpointAsync). A 200 therefore means
// something other than IMDSv2 answered and is not success.
func TestProbeOmitsMetadataHeaderAndAcceptsOnly400(t *testing.T) {
	for name, tc := range map[string]struct {
		status    int
		wantProbe bool
	}{
		"400 is the answer": {status: http.StatusBadRequest, wantProbe: true},
		"200 is not":        {status: http.StatusOK, wantProbe: false},
	} {
		t.Run(name, func(t *testing.T) {
			withCleanCaches(t)
			var sawMetadataHeader bool
			var probed bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "getplatformmetadata") {
					probed = true
					if r.Header.Get("Metadata") != "" {
						sawMetadataHeader = true
					}
					w.WriteHeader(tc.status)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(srv.Close)
			t.Setenv(identityEndpointEnvVar, "")
			t.Setenv(msiEndpointEnvVar, "")
			t.Setenv(identityHeaderEnvVar, "")
			t.Setenv(imdsEndVar, "")
			t.Setenv(msiSecretEnvVar, "")
			t.Setenv(identityServerThumbprintEnvVar, "")
			t.Setenv(azurePodIdentityAuthorityHostEnvVar, srv.URL)

			client, err := New(SystemAssigned(), WithHTTPClient(srv.Client()), WithRetryPolicyDisabled())
			if err != nil {
				t.Fatal(err)
			}
			client.keyProvider = newFakeKeyProvider()

			capabilities, err := client.Capabilities(context.Background())
			if err != nil {
				t.Fatalf("Capabilities: %v", err)
			}
			if !probed {
				t.Fatal("the probe never reached the metadata endpoint")
			}
			if sawMetadataHeader {
				t.Fatal("the probe sent a Metadata header; .NET's omits it so the endpoint answers 400")
			}
			got := capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthNone
			if got != tc.wantProbe {
				t.Fatalf("strength = %s, want a %t probe result for status %d",
					capabilities.MaxSupportedBindingStrength, tc.wantProbe, tc.status)
			}
		})
	}
}

// A transient failure is not the host's answer, so it must not become the
// answer for the rest of the process. One IMDS blip while a service starts up
// would otherwise leave a fully KeyGuard-capable host reporting None, failing
// every WithMtlsPoPMinStrength acquisition until the process restarted.
func TestCapabilitiesReprobesAfterATransientFailure(t *testing.T) {
	withCleanCaches(t)
	realNow := now
	current := realNow()
	now = func() time.Time { return current }
	t.Cleanup(func() { now = realNow })

	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusInternalServerError
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	got, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if got.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
		t.Fatalf("strength = %s, want None while IMDS is failing", got.MaxSupportedBindingStrength)
	}

	// IMDS recovers, but the failed answer is still inside its reuse window, so
	// the host is deliberately not asked again yet.
	fake.metadataStatus = http.StatusOK
	fake.calls = nil
	if _, err = client.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %q, want the failure reused inside the retry interval", fake.calls)
	}

	// Past the window it is asked again, and now gets a real answer.
	current = current.Add(capabilitiesRetryInterval + time.Second)
	if got, err = client.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if len(fake.calls) == 0 {
		t.Fatal("want a re-probe once the retry interval elapsed, got none")
	}
	if got.MaxSupportedBindingStrength != MtlsBindingStrengthKeyGuard {
		t.Fatalf("strength = %s, want KeyGuard once IMDS recovered", got.MaxSupportedBindingStrength)
	}
}

// The complement of the test above. A 404 is the host stating that it serves
// IMDSv1 only, which cannot change under a running process, so it must still be
// cached for good: without this, re-probing transient failures would degrade
// into probing every v1-only host on every call.
func TestCapabilitiesCachesAV1OnlyHostForTheProcessLifetime(t *testing.T) {
	withCleanCaches(t)
	realNow := now
	current := realNow()
	now = func() time.Time { return current }
	t.Cleanup(func() { now = realNow })

	fake := newIMDSFake(t)
	fake.metadataStatus = http.StatusNotFound
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	if _, err := client.Capabilities(context.Background()); err != nil {
		t.Fatalf("Capabilities: %v", err)
	}

	fake.calls = nil
	current = current.Add(100 * capabilitiesRetryInterval)
	got, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("calls = %q, want a v1-only host answered from cache forever", fake.calls)
	}
	if got.MaxSupportedBindingStrength != MtlsBindingStrengthNone {
		t.Fatalf("strength = %s, want None on a v1-only host", got.MaxSupportedBindingStrength)
	}
}

// The two policies differ in exactly one status code. Anything else drifting
// apart would be a divergence from MSAL .NET rather than a deliberate choice.
func TestProbeRetryPolicyDiffersFromAcquisitionOnlyOn404(t *testing.T) {
	for status := 100; status < 600; status++ {
		want := imdsRetriableStatus(status)
		if status == http.StatusNotFound {
			want = false
		}
		if got := imdsProbeRetriableStatus(status); got != want {
			t.Errorf("imdsProbeRetriableStatus(%d) = %t, want %t", status, got, want)
		}
	}
	if imdsProbeRetriableStatus(http.StatusNotFound) {
		t.Error("the probe must not retry a 404")
	}
	if !imdsRetriableStatus(http.StatusNotFound) {
		t.Error("the acquisition path must still retry a 404")
	}
}

// The Azure Arc agent installs its executable under Program Files; ProgramData
// holds only its runtime state, which is where the token directory lives. MSAL
// .NET probes %Programfiles%\AzureConnectedMachineAgent\himds.exe
// (ManagedIdentityClient.WindowsHimdsFilePath), and a library looking in the
// wrong directory reports no Azure Arc identity on a machine that has one.
func TestAzureArcWindowsPathsMatchDotNet(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the Windows paths are only meaningful on Windows")
	}
	himds := getAzureArcHimdsFilePath("windows")
	if want := filepath.Join(os.Getenv("ProgramFiles"), "AzureConnectedMachineAgent", "himds.exe"); himds != want {
		t.Errorf("himds path = %q, want %q", himds, want)
	}
	// The token directory is genuinely under ProgramData in .NET too
	// (ManagedIdentityClient.WindowsTokenPath). Only the executable moved.
	tokens := getAzureArcPlatformPath("windows")
	if want := filepath.Join(os.Getenv("ProgramData"), "AzureConnectedMachineAgent", "Tokens"); tokens != want {
		t.Errorf("token path = %q, want %q", tokens, want)
	}
}

// Client capabilities and a server-issued challenge share the token request's
// single claims parameter, so they have to be merged rather than one dropped.
func TestClientCapabilitiesReachTheTokenRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		capabilities []string
		claims       string
		want         string
	}{
		"capabilities alone": {
			capabilities: []string{"CP1"},
			want:         `{"access_token":{"xms_cc":{"values":["CP1"]}}}`,
		},
		"capabilities merged with a challenge": {
			capabilities: []string{"CP1"},
			claims:       `{"access_token":{"nbf":{"essential":true,"value":"1701000000"}}}`,
			want:         `{"access_token":{"nbf":{"essential":true,"value":"1701000000"},"xms_cc":{"values":["CP1"]}}}`,
		},
		"challenge alone is passed through": {
			claims: `{"access_token":{"nbf":{"essential":true,"value":"1701000000"}}}`,
			want:   `{"access_token":{"nbf":{"essential":true,"value":"1701000000"}}}`,
		},
		"neither sends nothing": {},
	} {
		t.Run(name, func(t *testing.T) {
			withCleanCaches(t)
			fake := newIMDSFake(t)
			var opts []ClientOption
			if len(tc.capabilities) > 0 {
				opts = append(opts, WithClientCapabilities(tc.capabilities))
			}
			client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider(), opts...)

			acquire := []AcquireTokenOption{WithMtlsProofOfPossession()}
			if tc.claims != "" {
				acquire = append(acquire, WithClaims(tc.claims))
			}
			if _, err := client.AcquireToken(context.Background(), "https://vault.azure.net", acquire...); err != nil {
				t.Fatalf("AcquireToken: %v", err)
			}
			got := fake.lastTokenForm.Get("claims")
			if tc.want == "" {
				if got != "" {
					t.Fatalf("claims = %q, want the parameter omitted", got)
				}
				return
			}
			if !sameJSON(t, got, tc.want) {
				t.Fatalf("claims = %q, want %q", got, tc.want)
			}
		})
	}
}

func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatalf("the expected value is not JSON: %v", err)
	}
	return reflect.DeepEqual(x, y)
}
// Concurrent acquisitions on a cold cache must not become concurrent requests
// to the managed identity endpoint, which is a single per-machine service that
// answers 429 when several arrive at once. MSAL .NET holds a process-wide
// semaphore and re-reads the cache under it for exactly this reason
// (ManagedIdentityAuthRequest.s_semaphoreSlim). Without the re-read every
// waiter would go on to make the request the gate exists to prevent.
func TestConcurrentAcquisitionsMakeOneRequest(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	client := fake.newTestClient(t, SystemAssigned(), newFakeKeyProvider())

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = client.AcquireToken(context.Background(), "https://vault.azure.net", WithMtlsProofOfPossession())
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	tokens := 0
	for _, call := range fake.calls {
		if call == "token" {
			tokens++
		}
	}
	if tokens != 1 {
		t.Fatalf("calls = %q, want exactly one token request from %d concurrent callers", strings.Join(fake.calls, ","), callers)
	}
}

// The gate must not outlive the caller's patience: a goroutine waiting for it
// when its context is cancelled has to return rather than block until the
// holder finishes.
func TestTokenGateHonoursContextCancellation(t *testing.T) {
	release, err := acquireMITokenGate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := acquireMITokenGate(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the gate was acquired while another goroutine held it (err=%v)", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the waiter did not return after its context was cancelled")
	}
}

// IMDS is not consistent about which error fields it fills, and the
// correlationId it returns is the only handle a support engineer can use to
// find the request in the service's logs. MSAL .NET reads all of these
// (ManagedIdentityErrorResponse), so a Go caller filing the same incident has
// the same identifier to quote.
func TestIMDSErrorBodyFieldsAreReported(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want []string
	}{
		"oauth pair": {
			body: `{"error":"invalid_request","error_description":"bad thing"}`,
			want: []string{"invalid_request", "bad thing"},
		},
		"message only": {
			body: `{"message":"identity not found"}`,
			want: []string{"identity not found"},
		},
		"correlation id is appended": {
			body: `{"error":"invalid_request","correlationId":"7f3c-abcd"}`,
			want: []string{"invalid_request", "7f3c-abcd"},
		},
		"message with correlation id": {
			body: `{"message":"identity not found","correlationId":"7f3c-abcd"}`,
			want: []string{"identity not found", "7f3c-abcd"},
		},
		"non-json falls back to the raw body": {
			body: "  plain text failure  ",
			want: []string{"plain text failure"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := parseIMDSError([]byte(tc.body))
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("parseIMDSError(%q) = %q, want it to contain %q", tc.body, got, want)
				}
			}
		})
	}
}
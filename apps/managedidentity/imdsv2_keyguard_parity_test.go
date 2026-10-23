// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity

import (
	"context"
	"errors"
	"testing"
)

// MSAL .NET's Windows key provider falls back KeyGuard -> Hardware -> InMemory,
// while msal-go asks CNG only for a VBS-isolated key. That difference is real
// but it is not observable: .NET refuses every non-KeyGuard key before it mints
// a credential, so both libraries end at the same place.
//
// WindowsManagedIdentityKeyProvider.GetOrCreateKeyAsync produces the weaker
// tiers, and ImdsV2ManagedIdentitySource.AcquireMtlsBindingAsync then rejects
// them for both v2 flows:
//
//	if (_isMtlsPopRequested || _preferMsiV2)
//	{
//	    ...
//	    if (keyInfo.Type != ManagedIdentityKeyType.KeyGuard)
//	    {
//	        throw new MsalClientException(
//	            "credential_guard_not_available",
//	            $"[ImdsV2] {flowName} currently requires a KeyGuard key, but this
//	              host produced a '{keyInfo.Type}' key. ...");
//	    }
//	}
//
// On a host without VBS msal-go never reaches that comparison, because CNG
// rejects the isolation flag and createPersistedKey returns
// ErrCredentialGuardNotAvailable outright. The two routes have to stay
// interchangeable, so this test drives both of them:
//
//   - a provider that hands back a usable non-KeyGuard key, which is what .NET's
//     Hardware and InMemory tiers look like to the flow, and
//   - a provider that fails the way msal-go's CNG path actually fails.
//
// Each is checked against both v2 flows and against the capability report, since
// .NET's DetermineImdsV2BindingStrengthCoreAsync maps a non-KeyGuard key and a
// key-provider exception alike to MtlsBindingStrength.Software.
func TestKeyGuardRefusalMatchesDotNet(t *testing.T) {
	// A provider tier, named for the ManagedIdentityKeyType it stands in for.
	providers := []struct {
		dotNetTier string
		configure  func(*fakeKeyProvider)
	}{
		{
			// ManagedIdentityKeyType.Hardware / InMemory: .NET's fallback tiers
			// hand the flow a working key that simply is not VBS-isolated.
			dotNetTier: "Hardware/InMemory key",
			configure:  func(p *fakeKeyProvider) { p.typ = keyTypeSoftware },
		},
		{
			// msal-go's real route on the same host: CNG refuses
			// NCRYPT_USE_VIRTUAL_ISOLATION_FLAG, so no key is produced at all.
			dotNetTier: "no key at all",
			configure: func(p *fakeKeyProvider) {
				p.err = ErrCredentialGuardNotAvailable
			},
		},
	}

	flows := []struct {
		// dotNetFlag is the field ImdsV2ManagedIdentitySource tests.
		dotNetFlag string
		option     AcquireTokenOption
	}{
		{dotNetFlag: "_isMtlsPopRequested", option: WithMtlsProofOfPossession()},
		{dotNetFlag: "_preferMsiV2", option: WithRequestOverMtls()},
	}

	for _, provider := range providers {
		for _, flow := range flows {
			t.Run(provider.dotNetTier+"/"+flow.dotNetFlag, func(t *testing.T) {
				withCleanCaches(t)
				fake := newIMDSFake(t)
				keys := newFakeKeyProvider()
				provider.configure(keys)

				client := fake.newTestClient(t, SystemAssigned(), keys)
				fake.resetCalls()

				_, err := client.AcquireToken(context.Background(),
					"https://vault.azure.net", flow.option)
				if !errors.Is(err, ErrCredentialGuardNotAvailable) {
					t.Fatalf("AcquireToken = %v, want ErrCredentialGuardNotAvailable; "+
						"MSAL .NET raises credential_guard_not_available for this tier", err)
				}
				// .NET performs this check before requesting a credential, so a
				// host that can never satisfy the flow must not consume one.
				if issued := fake.countOf("issue"); issued != 0 {
					t.Fatalf("issuecredential called %d times; the refusal must "+
						"precede the credential request as it does in .NET", issued)
				}

				// Same host, same key provider: the capability report still has
				// to claim the software floor, matching .NET mapping both a
				// non-KeyGuard key and a provider exception to Software.
				capabilities, err := client.Capabilities(context.Background())
				if err != nil {
					t.Fatalf("Capabilities: %v", err)
				}
				if capabilities.MaxSupportedBindingStrength != MtlsBindingStrengthSoftware {
					t.Fatalf("MaxSupportedBindingStrength = %s, want Software",
						capabilities.MaxSupportedBindingStrength)
				}
				// This is the exact situation .NET's error message calls out:
				// "The host may report Software-strength binding capability
				// (which means it can bind a token to a key), but the IMDSv2
				// attested flow only accepts VBS-isolated KeyGuard keys today."
				// So the host does still report that it can bind, and the
				// acquisition above still fails. Both halves have to hold, or
				// callers cannot tell the two tiers apart.
				if !capabilities.IsMtlsPoPSupportedByHost() {
					t.Fatal("a host that answered the v2 metadata call can bind " +
						"at software strength, matching .NET's IsMtlsPopSupported")
				}
			})
		}
	}
}

// The refusal has to survive a KeyGuard-capable host, or the test above would
// pass just as well against a library that refused everything.
func TestKeyGuardHostIsStillAccepted(t *testing.T) {
	withCleanCaches(t)
	fake := newIMDSFake(t)
	keys := newFakeKeyProvider() // defaults to keyTypeKeyGuard

	client := fake.newTestClient(t, SystemAssigned(), keys)
	for _, flow := range []struct {
		name   string
		option AcquireTokenOption
	}{
		{name: "mtls_pop", option: WithMtlsProofOfPossession()},
		{name: "mtls_bearer", option: WithRequestOverMtls()},
	} {
		t.Run(flow.name, func(t *testing.T) {
			if _, err := client.AcquireToken(context.Background(),
				"https://vault.azure.net", flow.option); err != nil {
				t.Fatalf("AcquireToken on a KeyGuard host: %v", err)
			}
		})
	}
}

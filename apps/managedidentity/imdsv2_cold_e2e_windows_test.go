// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build e2e && windows
// +build e2e,windows

package managedidentity

import (
	"os"
	"testing"
)

const coldAttestationE2EEnvVar = "IMDSV2_E2E_COLD_ATTESTATION"

// TestPrepareColdAttestationSystemAssigned removes only the exact attested
// system-assigned certificate alias used by this dedicated E2E agent. The
// KeyGuard container is deliberately retained.
func TestPrepareColdAttestationSystemAssigned(t *testing.T) {
	if os.Getenv(coldAttestationE2EEnvVar) != "true" {
		t.Skipf("set %s=true to prepare the cold attestation E2E path", coldAttestationE2EEnvVar)
	}

	store := windowsPersistentCertCache{}
	alias := cacheKey(SystemAssigned(), true)
	before := countRealStore(t, alias)
	store.deleteAll(alias)
	if after := countRealStore(t, alias); after != 0 {
		t.Fatalf("exact persisted alias %q still has %d certificates after deletion", alias, after)
	}
	t.Logf("cold attestation path prepared: exact persisted alias %q is absent (%d entries removed); "+
		"the shared KeyGuard key was retained", alias, before)
}

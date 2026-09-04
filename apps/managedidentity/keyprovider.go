// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"crypto"
	"errors"
	"fmt"
	"runtime"
)

// ErrMtlsNotSupportedForPlatform is returned when mTLS proof-of-possession or a
// request over mTLS is asked for on a platform that cannot produce a KeyGuard
// key. IMDSv2 binds a token to a key that the host must be able to isolate, and
// only Windows exposes such a key today, so on every other platform the request
// fails here rather than falling back to a weaker credential.
//
// Match it with errors.Is.
var ErrMtlsNotSupportedForPlatform = errors.New(
	"managedidentity: mTLS proof-of-possession for managed identity requires a KeyGuard key, which is only available on Windows")

// ErrCredentialGuardNotAvailable is returned when the host is Windows but does
// not offer a VBS-isolated key, which usually means Virtualization Based
// Security or Credential Guard is switched off. The token request is failed
// rather than silently downgraded to a software key.
//
// Match it with errors.Is.
var ErrCredentialGuardNotAvailable = errors.New(
	"managedidentity: this host cannot produce a KeyGuard key; check that Virtualization Based Security and Credential Guard are enabled")

// ErrMtlsPoPNotSupportedInIMDSv1 is returned when the host only answers the
// IMDSv1 token endpoint. Such a host cannot issue a binding certificate, so
// there is no way to satisfy a proof-of-possession request on it.
//
// Match it with errors.Is.
var ErrMtlsPoPNotSupportedInIMDSv1 = errors.New(
	"managedidentity: this host only supports IMDSv1, which cannot issue the binding certificate an mTLS proof-of-possession token requires")

// ErrMtlsPoPNotSupportedForSource is returned when mTLS proof-of-possession is
// requested somewhere other than an IMDS host. App Service, Service Fabric,
// Cloud Shell, Azure ML and Azure Arc have no credential issuance endpoint.
//
// Match it with errors.Is.
var ErrMtlsPoPNotSupportedForSource = errors.New(
	"managedidentity: mTLS proof-of-possession for managed identity is only supported on Azure VMs served by IMDS")

// ErrMtlsPoPAndBearerExclusive is returned when a single request asks for both
// WithMtlsProofOfPossession and WithRequestOverMtls. They select different token
// types, so asking for both is a programming error rather than a preference.
//
// Match it with errors.Is.
var ErrMtlsPoPAndBearerExclusive = errors.New(
	"managedidentity: WithMtlsProofOfPossession and WithRequestOverMtls cannot be combined; choose one")

// ErrAttestationRequiresMtls is returned when WithAttestationSupport is used on
// its own. Attestation only has meaning for a binding key, and a binding key is
// only minted on the IMDSv2 certificate path, so the option cannot be satisfied
// unless the request also selects that path. Returning an error rather than
// ignoring the option keeps the guarantee WithAttestationSupport documents: a
// caller that asked for attestation is never silently given a credential that
// lacks it.
//
// Match it with errors.Is.
var ErrAttestationRequiresMtls = errors.New(
	"managedidentity: WithAttestationSupport requires WithMtlsProofOfPossession or WithRequestOverMtls")

// keyType describes how well protected a binding key is.
type keyType int

const (
	keyTypeUnknown keyType = iota
	// keyTypeSoftware is an ordinary key whose private material is readable by
	// the process that holds it.
	keyTypeSoftware
	// keyTypeKeyGuard is a VBS-isolated key. Its private material is held by the
	// virtualization trustlet and never enters the process, so possession of the
	// bound token cannot be transferred by copying key bytes out of memory.
	keyTypeKeyGuard
)

func (k keyType) String() string {
	switch k {
	case keyTypeSoftware:
		return "Software"
	case keyTypeKeyGuard:
		return "KeyGuard"
	case keyTypeUnknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// bindingKey is the key IMDSv2 binds a certificate, and therefore a token, to.
//
// Signer never exposes private material: on Windows it is a handle to a CNG key
// that lives inside the VBS trustlet.
type bindingKey struct {
	Signer crypto.Signer
	Type   keyType
	// Close releases any operating system handle behind Signer. It is safe to
	// call more than once.
	Close func() error
}

// keyProvider produces the binding key for the IMDSv2 flow. It is an interface
// so tests can substitute a software key without a VBS-capable host, and so the
// Windows implementation can be compiled out elsewhere.
type keyProvider interface {
	// getOrCreateKey returns the binding key for name, creating it if it does
	// not already exist. Callers must call bindingKey.Close when finished.
	getOrCreateKey(name string) (bindingKey, error)
	// deleteKey removes the persisted key called name, so a caller can recover
	// from a key that IMDS or Entra will no longer accept.
	deleteKey(name string) error
}

// requireKeyGuard enforces the same rule MSAL .NET applies: a token bound by
// IMDSv2 must be bound to a VBS-isolated key. A software key would still
// produce a syntactically valid proof-of-possession token while offering none
// of its guarantees, so anything weaker is refused.
//
// This mirrors the check in ImdsV2ManagedIdentitySource.AcquireMtlsBindingAsync,
// which runs for both v2 flows (_isMtlsPopRequested || _preferMsiV2) and throws
// credential_guard_not_available when keyInfo.Type is not KeyGuard. .NET reaches
// that check holding a hardware or in-memory key, because its Windows provider
// falls back; msal-go asks CNG only for an isolated key, so on the same host it
// fails earlier, in createPersistedKey, with the same error. Both routes are
// pinned by TestKeyGuardRefusalMatchesDotNet.
func requireKeyGuard(key bindingKey) error {
	if key.Type == keyTypeKeyGuard {
		return nil
	}
	return fmt.Errorf("%w (this host produced a %s key)", ErrCredentialGuardNotAvailable, key.Type)
}

// platformSupportsMtlsPoP reports whether this build can produce a KeyGuard key
// at all. It is a compile-time property, not a runtime probe: a non-Windows
// build has no CNG to ask.
//
// It is a variable so the flow tests, which inject a software key, can exercise
// the protocol on every platform the library builds for rather than only on
// Windows.
var platformSupportsMtlsPoP = func() bool {
	return runtime.GOOS == "windows"
}

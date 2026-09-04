// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MtlsBindingStrength describes how strongly a token can be bound to a
// cryptographic key on the current host. Higher values bind more strongly.
//
// The value describes what the host is capable of producing, not what any
// particular request used. A value above [MtlsBindingStrengthNone] means the
// host can bind a token to a key; on its own it does not imply hardware
// attestation, which is specifically the [MtlsBindingStrengthKeyGuard] tier.
//
// The numbering matches MSAL .NET's MtlsBindingStrength so the two libraries
// describe a host the same way, including the gap at 2.
type MtlsBindingStrength int

const (
	// MtlsBindingStrengthNone means no key binding is available, so the host
	// cannot perform mTLS proof-of-possession at all.
	MtlsBindingStrengthNone MtlsBindingStrength = 0

	// MtlsBindingStrengthSoftware means the host can bind a token to a
	// software-backed key. The key is not hardware-isolated.
	//
	// This library will not itself bind to a software key: the IMDSv2 flow
	// requires a VBS-isolated key, so a host reporting this tier can speak the
	// protocol but an acquisition on it fails with
	// [ErrCredentialGuardNotAvailable]. The tier is still reported faithfully,
	// because it describes the host and is what MSAL .NET reports for the same
	// machine.
	//
	// MSAL .NET refuses this tier too. Its Windows key provider falls back to a
	// hardware or in-memory key when KeyGuard is unavailable, but
	// ImdsV2ManagedIdentitySource.AcquireMtlsBindingAsync then rejects any key
	// that is not KeyGuard, raising credential_guard_not_available. The extra
	// tiers change the diagnostics, not the outcome.
	MtlsBindingStrengthSoftware MtlsBindingStrength = 1

	// 2 is reserved for a future tier, for example TPM-backed keys. MSAL .NET
	// reserves the same value, so it is skipped here rather than reused.

	// MtlsBindingStrengthKeyGuard means the host can bind a token to a key
	// isolated by Virtualization-based Security, as on a Trusted Launch or
	// Confidential virtual machine. This is the only tier that implies
	// hardware-backed attestation.
	MtlsBindingStrengthKeyGuard MtlsBindingStrength = 3
)

func (s MtlsBindingStrength) String() string {
	switch s {
	case MtlsBindingStrengthNone:
		return "None"
	case MtlsBindingStrengthSoftware:
		return "Software"
	case MtlsBindingStrengthKeyGuard:
		return "KeyGuard"
	default:
		return fmt.Sprintf("MtlsBindingStrength(%d)", int(s))
	}
}

// ErrMinStrengthNotMet is returned when the host cannot bind a token as
// strongly as [WithMtlsPoPMinStrength] requires.
//
// It is raised before any certificate is minted, so a caller that requires
// attestation learns the host cannot provide it without having asked IMDS for a
// credential it would not have accepted.
var ErrMinStrengthNotMet = errors.New(
	"managedidentity: this host cannot bind a token as strongly as the requested minimum")

// ErrMinStrengthRequiresMtls is returned when [WithMtlsPoPMinStrength] is used
// without a request that binds a key. A floor describes the key a token is
// bound to, so it means nothing to a plain bearer request.
var ErrMinStrengthRequiresMtls = errors.New(
	"managedidentity: WithMtlsPoPMinStrength requires WithMtlsProofOfPossession or WithRequestOverMtls")

// Capabilities describes what the current host can do for managed identity.
//
// It is meant for credential chains, which have to decide whether to use
// managed identity at all and how strongly a token from it would be bound,
// before committing to an acquisition. It mirrors MSAL .NET's
// ManagedIdentityCapabilities.
type Capabilities struct {
	// Source is the managed identity source detected on this host, or the empty
	// string when none was found. The IMDS v1/v2 distinction is deliberately not
	// surfaced: both report [DefaultToIMDS], and the binding strength is the
	// signal that actually distinguishes them.
	Source Source

	// MaxSupportedBindingStrength is the strongest binding this host can
	// produce. This is the signal to branch on rather than the source label.
	MaxSupportedBindingStrength MtlsBindingStrength

	// ErrorReason describes why no source was detected, and is empty when one
	// was.
	ErrorReason string
}

// IsMtlsPoPSupportedByHost reports whether the host can bind a token to a key.
//
// It does not imply attestation. A caller that requires an attested credential
// must check that MaxSupportedBindingStrength is
// [MtlsBindingStrengthKeyGuard].
func (c Capabilities) IsMtlsPoPSupportedByHost() bool {
	return c.MaxSupportedBindingStrength > MtlsBindingStrengthNone
}

// capabilitiesCache holds the discovery result for the process.
//
// Discovery probes the metadata service and provisions a binding key, neither
// of which is cheap and neither of which changes while the process runs, so it
// is done once. gate makes it single-flight: concurrent callers at startup wait
// for the first probe rather than each issuing their own, which is what would
// otherwise happen in a service that resolves credentials on many goroutines at
// once. MSAL .NET does the same with a static field and a semaphore.
//
// gate is a channel rather than the mutex because discovery makes network calls
// and a failing metadata service can hold a probe for a minute of retries.
// Waiting behind the mutex would make every queued caller ignore its own
// deadline; a channel lets one give up. mu therefore only ever covers the two
// field accesses.
//
// expires separates the two kinds of negative answer. A definitive one - "this
// host serves IMDSv1 only", "this platform has no key provider" - is a fact
// about the host that cannot change while the process runs, so it is stored
// with a zero expires and never revisited. A transient failure is not an answer
// at all, so it is only reused until expires.
var capabilitiesCache = struct {
	mu      sync.Mutex
	gate    chan struct{}
	result  *Capabilities
	expires time.Time
}{gate: make(chan struct{}, 1)}

// capabilitiesRetryInterval is how long a transient discovery failure is reused
// before the host is probed again.
//
// It bounds two opposite costs. Caching such a failure for the life of the
// process leaves a fully capable host reporting MtlsBindingStrengthNone until
// it restarts, because nothing else invalidates the entry. Never caching it
// makes every caller pay a full probe, retries included, against a service that
// is already failing, which is the worst moment to add load to it.
const capabilitiesRetryInterval = 30 * time.Second

func clearCapabilitiesCache() {
	capabilitiesCache.mu.Lock()
	defer capabilitiesCache.mu.Unlock()
	capabilitiesCache.result = nil
	capabilitiesCache.expires = time.Time{}
}

// Capabilities reports what this host can do for managed identity.
//
// The result is discovered once and reused for the lifetime of the process.
// Discovery reads the environment first, and only probes the metadata service
// when no environment-based source is configured.
//
// An error is returned only when the context is cancelled. A host with no
// managed identity at all is not an error: it is reported as a Capabilities
// with an empty Source and a populated ErrorReason, because "there is no
// managed identity here" is an answer a credential chain acts on rather than a
// failure.
//
// A transient failure to reach the metadata service is reported the same way,
// but is not taken as the host's settled answer: it is reused for at most
// capabilitiesRetryInterval and then re-probed, so a host that was briefly
// unreachable is not written off for the life of the process.
func (c Client) Capabilities(ctx context.Context) (Capabilities, error) {
	if result, ok := cachedCapabilities(); ok {
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	select {
	case capabilitiesCache.gate <- struct{}{}:
	case <-ctx.Done():
		return Capabilities{}, ctx.Err()
	}
	defer func() { <-capabilitiesCache.gate }()

	// Whoever held the gate may have answered the question while this caller
	// was queued behind it.
	if result, ok := cachedCapabilities(); ok {
		return result, nil
	}

	result, definitive := c.discoverCapabilities(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// A result reached under a cancelled context may be the cancellation
		// rather than the host's answer, and caching it would make one
		// cancelled call poison every later one.
		return Capabilities{}, ctxErr
	}
	storeCapabilities(result, definitive)
	return result, nil
}

func cachedCapabilities() (Capabilities, bool) {
	capabilitiesCache.mu.Lock()
	defer capabilitiesCache.mu.Unlock()
	if capabilitiesCache.result != nil &&
		(capabilitiesCache.expires.IsZero() || now().Before(capabilitiesCache.expires)) {
		return *capabilitiesCache.result, true
	}
	return Capabilities{}, false
}

func storeCapabilities(result Capabilities, definitive bool) {
	capabilitiesCache.mu.Lock()
	defer capabilitiesCache.mu.Unlock()
	capabilitiesCache.result = &result
	if definitive {
		capabilitiesCache.expires = time.Time{}
	} else {
		capabilitiesCache.expires = now().Add(capabilitiesRetryInterval)
	}
}

// discoverCapabilities works out what this host supports. The second return
// reports whether the answer is definitive: a fact about the host rather than a
// failure that may not repeat. Only a definitive answer is cached for the life
// of the process.
func (c Client) discoverCapabilities(ctx context.Context) (Capabilities, bool) {
	// An environment-configured source is authoritative and costs nothing to
	// read, so it settles the question without a probe. None of these sources
	// issues a binding certificate, so none of them can bind a token.
	if c.source != DefaultToIMDS {
		return Capabilities{Source: c.source, MaxSupportedBindingStrength: MtlsBindingStrengthNone}, true
	}

	// IMDSv2 is probed before falling back to v1. The v2 endpoint only exists
	// on hosts that serve it, whereas v1 answers a malformed request with 400,
	// so probing v1 first would report success on a host that also serves v2
	// and mask its stronger binding.
	if !platformSupportsMtlsPoP() {
		// The v2 flow needs a platform key. Without one there is nothing to
		// bind to, and the probe would only prove IMDS is reachable, which the
		// v1 answer below already covers.
		return Capabilities{
			Source:                      DefaultToIMDS,
			MaxSupportedBindingStrength: MtlsBindingStrengthNone,
			ErrorReason:                 ErrMtlsNotSupportedForPlatform.Error(),
		}, true
	}

	v := imdsV2{
		httpClient:   c.httpClient,
		keyProvider:  c.bindingKeyProvider(),
		miType:       c.miType,
		retryEnabled: c.retryPolicyEnabled,
		baseEndpoint: imdsV2BaseEndpoint(),
	}
	if err := v.probeEndpoint(ctx, newCorrelationID()); err != nil {
		// MSAL .NET falls through to the IMDSv1 question on any v2 probe
		// failure, not only on the one that says "no such endpoint"
		// (ManagedIdentityClient.GetManagedIdentitySourceAsync: "If v2 fails,
		// fall back to probing IMDS v1"), so a host that is briefly unwell on
		// the v2 route still gets described from its compute document rather
		// than reported as having no managed identity at all.
		//
		// Whether that description is worth remembering is a separate question.
		// A 404 is the host answering that it has no v2 route, which is settled
		// and cannot change under a running process. Anything else - a 5xx, a
		// throttle, a timeout - is a failure to obtain an answer rather than an
		// answer, and the retries above have already given it every chance, so
		// the answer below is used but not cached. (.NET caches either outcome
		// for the life of the process; a transient 500 there disables managed
		// identity permanently.)
		definitive := errors.Is(err, ErrMtlsPoPNotSupportedInIMDSv1)
		return capabilitiesForIMDSv1(v, ctx, err), definitive
	}

	return Capabilities{
		Source:                      DefaultToIMDS,
		MaxSupportedBindingStrength: bindingStrengthFor(v.keyProvider),
	}, true
}

// capabilitiesForIMDSv1 describes a host that has answered that it serves
// IMDSv1 only.
//
// Such a host cannot run the v2 CSR flow, so this library will not mint a
// binding certificate on it. The tier is still reported from the instance
// compute document, because Capabilities describes the host rather than what
// this library will do with it: a credential chain uses it to decide whether
// managed identity is worth attempting at all, and MSAL .NET reports the same
// tier for the same machine from the same document
// (ManagedIdentityClient.DetermineImdsV1BindingStrengthAsync). Reporting None
// where .NET reports Software would make the two libraries disagree about a
// machine.
//
// Software is the ceiling here, deliberately. A security profile is a statement
// about the platform, not a successful VBS attestation, so claiming the attested
// KeyGuard tier from it would overclaim; .NET makes the same choice and says so.
//
// Any failure to read the document reports no binding, matching .NET's
// treatment of a null response. The v2 failure is reported as the reason only
// when the answer is that nothing can bind, because a host that did produce a
// tier has been described successfully and has no error to report.
func capabilitiesForIMDSv1(v imdsV2, ctx context.Context, v2Err error) Capabilities {
	compute, err := v.getComputeMetadata(ctx, newCorrelationID())
	if err == nil && compute.supportsMtlsPoP() {
		return Capabilities{
			Source:                      DefaultToIMDS,
			MaxSupportedBindingStrength: MtlsBindingStrengthSoftware,
		}
	}
	return Capabilities{
		Source:                      DefaultToIMDS,
		MaxSupportedBindingStrength: MtlsBindingStrengthNone,
		ErrorReason:                 v2Err.Error(),
	}
}

// bindingStrengthFor reports the strongest binding a host that already answered
// the IMDSv2 metadata call can produce.
//
// Answering that call proves the host speaks the key-bound CSR protocol, so it
// can bind at least at software strength. Whether it can do better depends on
// the key the platform hands back: only a VBS-isolated key justifies claiming
// the attested tier.
//
// A key provider that fails leaves the software floor in place rather than
// reporting no binding at all. The host demonstrably speaks the protocol; a key
// that could not be provisioned right now is a local condition, and reporting
// None would tell a credential chain to abandon managed identity over it.
func bindingStrengthFor(provider keyProvider) MtlsBindingStrength {
	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		return MtlsBindingStrengthSoftware
	}
	defer func() {
		if key.Close != nil {
			_ = key.Close()
		}
	}()
	if key.Type == keyTypeKeyGuard {
		return MtlsBindingStrengthKeyGuard
	}
	return MtlsBindingStrengthSoftware
}

// enforceMinStrength fails an acquisition whose host cannot bind as strongly as
// the caller requires.
//
// It runs before a certificate is minted. Discovering the shortfall afterwards
// would mean IMDS had already issued a credential the caller was always going
// to refuse, and on a host with no VBS the caller would learn only from the
// key provider's error, which describes the key rather than the requirement
// that was not met.
func (c Client) enforceMinStrength(ctx context.Context, min MtlsBindingStrength) error {
	if min <= MtlsBindingStrengthNone {
		return nil
	}
	capabilities, err := c.Capabilities(ctx)
	if err != nil {
		return err
	}
	if capabilities.MaxSupportedBindingStrength < min {
		return fmt.Errorf("%w: this host supports %s, the request requires at least %s",
			ErrMinStrengthNotMet, capabilities.MaxSupportedBindingStrength, min)
	}
	return nil
}

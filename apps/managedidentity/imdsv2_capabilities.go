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

// ErrInvalidMtlsBindingStrength is returned when [WithMtlsPoPMinStrength] is
// given a value that is not one of the declared tiers.
//
// MtlsBindingStrength is an exported integer type, so nothing in the type system
// stops a caller passing 2 - the value reserved for a future tier - or an
// arbitrary number. Such a value cannot be a floor: no host reports it, so it
// would either be silently rounded down to a weaker requirement than the caller
// wrote, or reject every host including ones that can bind at the strongest tier
// available. Refusing it names the mistake instead.
//
// Match it with errors.Is.
var ErrInvalidMtlsBindingStrength = errors.New(
	"managedidentity: the requested MtlsBindingStrength is not one of MtlsBindingStrengthNone, MtlsBindingStrengthSoftware or MtlsBindingStrengthKeyGuard")

// isDeclaredStrength reports whether s is one of the tiers this package defines.
func (s MtlsBindingStrength) isDeclared() bool {
	switch s {
	case MtlsBindingStrengthNone, MtlsBindingStrengthSoftware, MtlsBindingStrengthKeyGuard:
		return true
	}
	return false
}

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

	// ErrorReason carries diagnostic detail when discovery, or the attempt to
	// determine the binding strength, did not fully succeed. It is not a
	// reliable signal that binding is unavailable, and it is not populated for
	// every host that cannot bind.
	//
	// It is set when no managed identity source was detected, when the compute
	// document that names the IMDSv1 tier could not be read or parsed, when the
	// key provider could not produce a key to measure the tier from - which
	// includes a build whose platform has no provider at all - and on an
	// IMDSv1-only host whose compute document was read successfully and says the
	// host cannot bind, where it carries the IMDSv2 probe's answer. A populated
	// ErrorReason alongside [DefaultToIMDS] is therefore ordinary, and says
	// managed identity works here while a bound token does not.
	//
	// It is empty for an environment-configured source that simply does not
	// support binding. App Service, Cloud Shell, Azure ML, Service Fabric and
	// Azure Arc issue no binding certificate, so [MtlsBindingStrengthNone]
	// there is the complete answer and nothing failed to produce it. Branch on
	// MaxSupportedBindingStrength, and read ErrorReason for the explanation.
	ErrorReason string
}

// IsMtlsPoPSupportedByHost reports whether the host can bind a token to a key.
//
// It describes the host, not what an acquisition here will do with it. Two
// things follow from that, and both matter to a caller branching on this value:
//
// It does not imply attestation. Only [MtlsBindingStrengthKeyGuard] means the
// key is VBS-isolated, which is the tier an attested credential needs.
//
// It does not imply that an mTLS acquisition will succeed. This library binds
// only to a KeyGuard key, so a host reporting [MtlsBindingStrengthSoftware]
// returns true here - it does speak the protocol, and MSAL .NET reports the same
// tier for the same machine - while [WithMtlsProofOfPossession] on it fails with
// [ErrCredentialGuardNotAvailable]. A caller deciding whether to attempt an
// acquisition should compare MaxSupportedBindingStrength against
// [MtlsBindingStrengthKeyGuard] rather than calling this.
func (c Capabilities) IsMtlsPoPSupportedByHost() bool {
	return c.MaxSupportedBindingStrength > MtlsBindingStrengthNone
}

// capabilitiesState holds one client's host-capability discovery result.
//
// It hangs off the Client rather than off a process-wide map, and that is the
// whole design. The answer depends on the client: a Client can carry its own
// HTTP client, its own key provider and its own metadata endpoint, all of which
// decide what discovery finds. A single shared entry would let the first client
// to call Capabilities publish its answer to every other client in the process -
// a real problem for an application that builds one client against a
// pod-identity sidecar and another against real IMDS, and for a test whose fake
// would become reachable from unrelated code.
//
// A keyed process-wide map was the obvious alternative and is worse, for two
// reasons that cannot be engineered around. It would have to identify an
// ops.HTTPClient and a keyProvider, which are arbitrary caller-supplied
// interface values: their dynamic types need not be comparable, so they cannot
// be part of a map key directly, and identifying them by the address behind the
// interface is unsound because Go reuses an address once the object it named is
// collected. A later, unrelated client could then be handed a definitive answer
// - one cached for the life of the process - that was discovered for an object
// that no longer exists. Such a map also never shrinks, so a process that builds
// clients over time accumulates an entry per client forever.
//
// Holding the state by reference from the Client removes both questions. The
// state lives exactly as long as the clients that share it and is collected with
// them, so nothing accumulates and no address is ever reused underneath a live
// entry. New gives each Client a state of its own, and because Client is a value
// type the pointer travels with every copy: copies of one client share an
// answer, independently constructed clients never do.
//
// expires separates the two kinds of negative answer. A definitive one - "this
// host serves IMDSv1 only", "this process is configured for an environment
// source that cannot bind" - is a fact that cannot change while the process
// runs, so it is stored with a zero expires and never revisited. A transient
// failure is not an answer at all, so it is only reused until expires.
type capabilitiesState struct {
	// gate makes discovery single-flight. Concurrent callers at startup wait
	// for the first probe rather than each issuing their own, which is what
	// would otherwise happen in a service that resolves credentials on many
	// goroutines at once. MSAL .NET does the same with a static field and a
	// semaphore.
	//
	// It is a channel rather than a mutex because discovery makes network calls
	// and a failing metadata service can hold a probe for a minute of retries.
	// Waiting behind a mutex would make every queued caller ignore its own
	// deadline; a channel lets one give up.
	gate chan struct{}

	// mu only ever covers the two fields below, never a network call.
	mu      sync.Mutex
	result  *Capabilities
	expires time.Time
}

func newCapabilitiesState() *capabilitiesState {
	return &capabilitiesState{gate: make(chan struct{}, 1)}
}

// cached returns a stored answer that is still good.
func (s *capabilitiesState) cached() (Capabilities, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.result != nil && (s.expires.IsZero() || now().Before(s.expires)) {
		return *s.result, true
	}
	return Capabilities{}, false
}

// store records an answer, keeping a definitive one for the life of the process
// and a transient one only until it expires.
func (s *capabilitiesState) store(result Capabilities, definitive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = &result
	if definitive {
		s.expires = time.Time{}
	} else {
		s.expires = now().Add(capabilitiesRetryInterval)
	}
}

// hostCapabilityState returns the discovery state for this client.
//
// A Client built by New always has one. A zero-value Client does not, and gets a
// throwaway state so that Capabilities still answers correctly; it simply does
// not cache, because there is nowhere on a value receiver to put the result that
// the caller would ever see again. Only tests construct a Client that way.
func (c Client) hostCapabilityState() *capabilitiesState {
	if c.hostCapabilities != nil {
		return c.hostCapabilities
	}
	return newCapabilitiesState()
}

// capabilitiesRetryInterval is how long a transient discovery failure is reused
// before the host is probed again.
//
// It bounds two opposite costs. Caching such a failure for the life of the
// process leaves a fully capable host reporting MtlsBindingStrengthNone until
// it restarts, because nothing else invalidates the entry. Never caching it
// makes every caller pay a full probe, retries included, against a service that
// is already failing, which is the worst moment to add load to it.
const capabilitiesRetryInterval = 30 * time.Second

// Capabilities reports what this host can do for managed identity.
//
// The result is discovered once per client and reused for the lifetime of that
// client. Copies of a client made by value share the result; independently
// constructed clients each discover their own, because each can be configured
// with a different HTTP client, key provider or metadata endpoint and would not
// necessarily get the same answer. Discovery reads the environment first, and
// only probes the metadata service when no environment-based source is
// configured.
//
// Discovery follows the order MSAL .NET uses, in
// ManagedIdentityClient.GetManagedIdentitySourceAsync: an environment-configured
// source settles it, otherwise IMDSv2 is probed, and if that fails IMDSv1 is
// probed too. Source is reported as [DefaultToIMDS] only once one of those
// probes has answered; when neither does it is left empty, because nothing has
// shown the host serves managed identity. The instance compute document is read
// only after the v1 probe succeeds, and only to decide that host's tier.
//
// Discovery is not purely a read. On a host that serves IMDSv2 it asks the
// platform for the binding key, which creates and persists that key if it does
// not already exist: a CNG container under a fixed name, shared with MSAL .NET
// and surviving process restarts. That is what makes the answer trustworthy -
// the tier reported is the tier of a key this host really produced, not a guess
// from a document - but it does mean calling Capabilities on a capable host
// leaves a key behind. No certificate and no token is minted, so nothing is
// requested from IMDS beyond the probe itself.
//
// An error is returned only when the context is cancelled. A host with no
// managed identity at all is not an error: it is reported as a Capabilities
// with an empty Source and a populated ErrorReason, because "there is no
// managed identity here" is an answer a credential chain acts on rather than a
// failure. A cancelled call caches nothing.
//
// How long an answer lasts depends on how settled it is, and the difference is
// visible to a caller that retries. A settled answer - an environment source, a
// successful v2 probe, or a definitive v2 absence followed by a successful v1
// probe whose compute document was read and parsed - cannot change under a
// running process and is kept for this client's lifetime. Anything unresolved is
// kept for at most capabilitiesRetryInterval, currently 30 seconds: a probe that
// could not be completed, a compute document that could not be read or parsed,
// or a v2 failure that was not a definitive 404, because v2 may recover and a
// client that remembered the weaker v1 answer for good would never notice.
//
// This is deliberately unlike MSAL .NET, which caches every outcome statically
// for the life of the process; there, one transient failure disables managed
// identity until restart. The per-client state is deliberate too: clients can
// carry different HTTP clients, key providers and metadata endpoints, so one
// client's answer is not generally valid for another.
func (c Client) Capabilities(ctx context.Context) (Capabilities, error) {
	state := c.hostCapabilityState()
	if result, ok := state.cached(); ok {
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return Capabilities{}, err
	}
	select {
	case state.gate <- struct{}{}:
	case <-ctx.Done():
		return Capabilities{}, ctx.Err()
	}
	defer func() { <-state.gate }()

	// Whoever held the gate may have answered the question while this caller
	// was queued behind it.
	if result, ok := state.cached(); ok {
		return result, nil
	}

	result, definitive := c.discoverCapabilities(ctx)
	if ctxErr := ctx.Err(); ctxErr != nil {
		// A result reached under a cancelled context may be the cancellation
		// rather than the host's answer, and caching it would make one
		// cancelled call poison every later one.
		return Capabilities{}, ctxErr
	}
	state.store(result, definitive)
	return result, nil
}

// discoverCapabilities works out what this host supports. The second return
// reports whether the answer is definitive: a fact about the host rather than a
// failure that may not repeat. Only a definitive answer is kept for the life of
// the client; anything else expires after capabilitiesRetryInterval.
//
// The order is MSAL .NET's, from ManagedIdentityClient.GetManagedIdentitySourceAsync:
// an environment-configured source settles it, otherwise probe IMDSv2, and if
// that fails probe IMDSv1. Only once a probe has answered is the host known to
// serve managed identity at all.
//
// The instance compute document is deliberately not part of establishing that.
// It describes the machine's security profile and answers on hosts with no
// managed identity endpoint whatsoever, so treating it as evidence of IMDSv1
// would report DefaultToIMDS for a host that has none. .NET reads it only after
// its v1 probe succeeds, and only to decide the tier; so does this.
//
// The probes run on every platform. Whether Go can mint a KeyGuard key is a
// separate question from whether the host serves managed identity, and
// conflating them would report "no source" on, say, a Linux VM that plainly has
// one. The platform limit shows up as the binding tier and as the error an
// actual acquisition returns, not as an absent source.
func (c Client) discoverCapabilities(ctx context.Context) (Capabilities, bool) {
	// An environment-configured source is authoritative and costs nothing to
	// read, so it settles the question without a probe. None of these sources
	// issues a binding certificate, so none of them can bind a token.
	if c.source != DefaultToIMDS {
		return Capabilities{Source: c.source, MaxSupportedBindingStrength: MtlsBindingStrengthNone}, true
	}

	v := imdsV2{
		httpClient:   c.httpClient,
		keyProvider:  c.bindingKeyProvider(),
		miType:       c.miType,
		retryEnabled: c.retryPolicyEnabled,
		baseEndpoint: imdsV2BaseEndpoint(),
	}

	v2Err := v.probeEndpoint(ctx, newCorrelationID())
	if v2Err == nil {
		// The host speaks the key-bound CSR protocol, so it can bind at least
		// at software strength; the platform key decides whether it can do
		// better. Whether that answer is settled is decided by the provider:
		// a key it actually produced is a fact about the host, while a provider
		// that failed for a local reason leaves the tier unknown and must not
		// be cached as though the host had answered.
		strength, reason, definitive := bindingStrengthFor(v.keyProvider)
		return Capabilities{
			Source:                      DefaultToIMDS,
			MaxSupportedBindingStrength: strength,
			ErrorReason:                 reason,
		}, definitive
	}
	if ctx.Err() != nil {
		return Capabilities{}, false
	}

	// v2 answered 404, which is the host saying it has no v2 route. Anything
	// else is a failure to get an answer, and v2 may recover, so an answer
	// reached after one is not kept for the life of the client.
	v2Definitive := errors.Is(v2Err, ErrMtlsPoPNotSupportedInIMDSv1)

	if v1Err := v.probeV1Endpoint(ctx, newCorrelationID()); v1Err != nil {
		if ctx.Err() != nil {
			return Capabilities{}, false
		}
		// Neither probe established IMDS. Source stays empty: reporting
		// DefaultToIMDS here would tell a credential chain there is an identity
		// endpoint when nothing has answered like one.
		return Capabilities{
			MaxSupportedBindingStrength: MtlsBindingStrengthNone,
			ErrorReason:                 fmt.Sprintf("%s; %s", v2Err, v1Err),
		}, false
	}

	// v1 is there. Its tier comes from the compute document, which is the same
	// source .NET reads in DetermineImdsV1BindingStrengthAsync, and Software is
	// the ceiling: a security profile is a statement about the platform, not a
	// successful VBS attestation.
	strength, computeErr := imdsV1BindingStrength(ctx, v)
	result := Capabilities{
		Source:                      DefaultToIMDS,
		MaxSupportedBindingStrength: strength,
	}
	if computeErr != nil {
		// The source is established either way; only the tier is unknown, and
		// the reason has to say so rather than repeating the v2 failure.
		result.ErrorReason = computeErr.Error()
		return result, false
	}
	if strength == MtlsBindingStrengthNone {
		result.ErrorReason = v2Err.Error()
	}
	// Permanent only when v2's absence was itself settled. A transient v2
	// failure means v2 may come back, and a client that cached this answer for
	// good would keep reporting the weaker v1 tier for a host that had
	// recovered.
	return result, v2Definitive
}

// imdsV1BindingStrength reads the tier for a host that has answered the IMDSv1
// probe. A failure to read or parse the compute document is reported, so the
// caller can tell "this host cannot bind" from "this host's tier is unknown".
func imdsV1BindingStrength(ctx context.Context, v imdsV2) (MtlsBindingStrength, error) {
	compute, err := v.getComputeMetadata(ctx, newCorrelationID())
	if err != nil {
		return MtlsBindingStrengthNone, fmt.Errorf("managedidentity: IMDSv1 is available but its binding strength could not be determined: %w", err)
	}
	if compute.supportsMtlsPoP() {
		return MtlsBindingStrengthSoftware, nil
	}
	return MtlsBindingStrengthNone, nil
}

// bindingStrengthFor reports the strongest binding a host that already answered
// the IMDSv2 metadata call can produce, a diagnostic when that could not be
// established, and whether the answer is settled.
//
// Answering that call proves the host speaks the key-bound CSR protocol, so it
// can bind at least at software strength. Whether it can do better depends on
// the key the platform hands back: only a VBS-isolated key justifies claiming
// the attested tier.
//
// This is the one place a key may be created outside an acquisition, and it is
// deliberate: the tier has to describe a key the host actually produced. Opening
// an existing key would answer for a host that has one and say nothing about a
// host that has never run this flow, which is exactly the host a credential
// chain is asking about. Capabilities documents the side effect.
//
// A key provider that fails leaves the software floor in place rather than
// reporting no binding at all. The host demonstrably speaks the protocol; a key
// that could not be provisioned right now is a local condition, and reporting
// None would tell a credential chain to abandon managed identity over it.
//
// What such a failure must not do is settle the question. Whether the host can
// reach the attested tier is unknown while the provider is failing, and caching
// "Software" for the life of the client would turn a passing condition - VBS
// still starting, the KSP briefly unavailable, a transient NTE_ error - into a
// permanent verdict that only a restart could clear. The third return therefore
// distinguishes the two kinds of failure:
//
//   - a key that was produced, at either tier, is a fact about the host and is
//     definitive;
//   - [ErrMtlsNotSupportedForPlatform] is definitive too, but for the opposite
//     reason: it is chosen at compile time by the build's key provider, so it
//     cannot change while this binary is running, and retrying it every thirty
//     seconds would only re-answer a settled question;
//   - anything else is indeterminate and is reported as transient, so the
//     thirty-second expiry re-asks once the local condition has had a chance to
//     clear.
//
// The strength continues to describe the host and the reason describes this
// process. A Linux build reports the software floor the host really has - the
// same tier MSAL .NET reports for that machine - together with a reason saying
// this build cannot mint the key. Acquisition remains KeyGuard-only either way.
func bindingStrengthFor(provider keyProvider) (MtlsBindingStrength, string, bool) {
	key, err := provider.getOrCreateKey(bindingKeyName)
	if err != nil {
		if errors.Is(err, ErrMtlsNotSupportedForPlatform) {
			return MtlsBindingStrengthSoftware, err.Error(), true
		}
		return MtlsBindingStrengthSoftware, err.Error(), false
	}
	defer func() {
		if key.Close != nil {
			_ = key.Close()
		}
	}()
	if key.Type == keyTypeKeyGuard {
		return MtlsBindingStrengthKeyGuard, "", true
	}
	return MtlsBindingStrengthSoftware, "", true
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

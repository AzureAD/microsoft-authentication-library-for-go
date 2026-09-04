// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build windows

package managedidentity

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file persists issued binding certificates in the current user's personal
// certificate store, so a restart reuses a credential instead of asking IMDS for
// a new one. IMDS rate limits credential issuance, so a fleet that restarts
// often is the case this exists for.
//
// It is a port of WindowsPersistentCertificateCache in MSAL .NET, down to the
// store, the friendly name grammar and the selection rules, so that the two
// libraries read and write the same entries.

var (
	crypt32DLL = windows.NewLazySystemDLL("crypt32.dll")

	procCertGetCertificateContextProperty = crypt32DLL.NewProc("CertGetCertificateContextProperty")
	procCertSetCertificateContextProperty = crypt32DLL.NewProc("CertSetCertificateContextProperty")
)

const (
	// certFriendlyNamePropID is CERT_FRIENDLY_NAME_PROP_ID.
	certFriendlyNamePropID = 11
	// certKeyProvInfoPropID is CERT_KEY_PROV_INFO_PROP_ID, the property that
	// ties a stored certificate to the key container holding its private key.
	certKeyProvInfoPropID = 2
	// certNCryptKeySpec is CERT_NCRYPT_KEY_SPEC, which marks the container as a
	// CNG key rather than a legacy CryptoAPI key pair.
	certNCryptKeySpec = 0xFFFFFFFF

	// persistLockTimeout is how long a store write waits for the cross-process
	// lock before giving up. It is short and deliberately not configurable:
	// persistence is an optimisation, so a busy lock skips the write rather
	// than delaying a token. MSAL .NET uses the same 300ms.
	persistLockTimeout = 300 * time.Millisecond
)

// cryptKeyProvInfo is CRYPT_KEY_PROV_INFO.
type cryptKeyProvInfo struct {
	containerName *uint16
	provName      *uint16
	provType      uint32
	flags         uint32
	provParam     uint32
	rgProvParam   uintptr
	keySpec       uint32
}

// cryptDataBlob is CRYPT_DATA_BLOB.
type cryptDataBlob struct {
	cbData uint32
	pbData *byte
}

type windowsPersistentCertCache struct{}

func newPlatformPersistentCertCache() persistentCertCache {
	return windowsPersistentCertCache{}
}

// openMyStore opens the current user's personal store.
func openMyStore(readOnly bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("My")
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.CERT_SYSTEM_STORE_CURRENT_USER)
	if readOnly {
		flags |= windows.CERT_STORE_READONLY_FLAG | windows.CERT_STORE_OPEN_EXISTING_FLAG
	}
	return windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		flags,
		uintptr(unsafe.Pointer(name)),
	)
}

// snapshotStore returns an owned duplicate of every certificate in the store.
//
// The contexts are duplicated rather than used in place because deleting during
// enumeration frees the context the enumeration is standing on. Taking a
// snapshot first keeps deletion away from the walk entirely, which is the same
// reason MSAL .NET copies the collection before iterating it.
//
// The caller must free every returned context.
func snapshotStore(store windows.Handle) []*windows.CertContext {
	var out []*windows.CertContext
	var ctx *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(store, ctx)
		if err != nil || next == nil {
			// The enumeration frees the context it was given once it runs out,
			// so there is nothing left to release here.
			return out
		}
		ctx = next
		if dup := windows.CertDuplicateCertificateContext(ctx); dup != nil {
			out = append(out, dup)
		}
	}
}

func freeContexts(contexts []*windows.CertContext) {
	for _, ctx := range contexts {
		_ = windows.CertFreeCertificateContext(ctx)
	}
}

// contextProperty reads a certificate property into a buffer.
func contextProperty(ctx *windows.CertContext, propID uint32) ([]byte, bool) {
	var size uint32
	ret, _, _ := syscall.SyscallN(
		procCertGetCertificateContextProperty.Addr(),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(propID),
		0,
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 || size == 0 {
		return nil, false
	}
	buf := make([]byte, size)
	ret, _, _ = syscall.SyscallN(
		procCertGetCertificateContextProperty.Addr(),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(propID),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return nil, false
	}
	return buf[:size], true
}

// friendlyName reads CERT_FRIENDLY_NAME_PROP_ID as a string.
func friendlyName(ctx *windows.CertContext) string {
	buf, ok := contextProperty(ctx, certFriendlyNamePropID)
	if !ok || len(buf) < 2 {
		return ""
	}
	chars := make([]uint16, len(buf)/2)
	for i := range chars {
		chars[i] = uint16(buf[2*i]) | uint16(buf[2*i+1])<<8
	}
	return windows.UTF16ToString(chars)
}

// usesBindingKeyContainer reports whether the stored certificate names the
// container the binding key lives in.
//
// This is what keeps the cache from touching unrelated certificates. The
// personal store is shared with everything else the user has, and an entry that
// merely decodes as an MSAL friendly name is still not ours to reuse or delete
// unless its private key is the one this library can open.
func usesBindingKeyContainer(ctx *windows.CertContext) bool {
	buf, ok := contextProperty(ctx, certKeyProvInfoPropID)
	if !ok || len(buf) < int(unsafe.Sizeof(cryptKeyProvInfo{})) {
		return false
	}
	info := (*cryptKeyProvInfo)(unsafe.Pointer(&buf[0]))
	if info.keySpec != certNCryptKeySpec {
		return false
	}
	// containerName and provName point at wide strings crypt32 appended inside
	// buf, so buf has to outlive the reads. The loaded pointers do keep the
	// backing array alive on their own, but buf is what the reader can see, and
	// keyCanSign and Sign hold their CNG structures the same way.
	defer runtime.KeepAlive(buf)
	return utf16PtrToString(info.containerName) == bindingKeyName &&
		utf16PtrToString(info.provName) == msKeyStorageProvider
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	return windows.UTF16PtrToString(p)
}

// certificateFrom decodes the DER a store context carries.
func certificateFrom(ctx *windows.CertContext) ([]byte, *x509.Certificate, bool) {
	if ctx == nil || ctx.EncodedCert == nil || ctx.Length == 0 {
		return nil, nil, false
	}
	der := make([]byte, ctx.Length)
	copy(der, unsafe.Slice(ctx.EncodedCert, ctx.Length))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, false
	}
	return der, leaf, true
}

func (w windowsPersistentCertCache) read(alias string) (*persistedCertificate, bool) {
	store, err := openMyStore(true)
	if err != nil {
		return nil, false
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()

	contexts := snapshotStore(store)
	defer freeContexts(contexts)

	var (
		best       *persistedCertificate
		bestExpiry time.Time
	)
	cutoff := now().Add(bindingCertRefreshWindow)

	for _, ctx := range contexts {
		name, endpoint, ok := decodeFriendlyName(friendlyName(ctx))
		if !ok || name != alias {
			continue
		}
		if !usesBindingKeyContainer(ctx) {
			continue
		}
		der, leaf, ok := certificateFrom(ctx)
		if !ok {
			continue
		}
		// A certificate with less than a token's lifetime left is not worth
		// reusing, for the reason bindingCertRefreshWindow documents.
		if !leaf.NotAfter.After(cutoff) {
			continue
		}
		clientID, ok := clientIDFromSubject(leaf)
		if !ok {
			continue
		}
		host, tenant, ok := splitEndpointBase(endpoint)
		if !ok {
			continue
		}
		if best == nil || leaf.NotAfter.After(bestExpiry) {
			best = &persistedCertificate{
				DER:      der,
				Leaf:     leaf,
				ClientID: clientID,
				TenantID: tenant,
				Endpoint: host,
			}
			bestExpiry = leaf.NotAfter
		}
	}
	return best, best != nil
}

// clientIDFromSubject reads the client ID out of the certificate subject.
//
// IMDS issues the credential with the managed identity's client ID as the
// common name, and that is the value the token request has to send. Reading it
// back from the certificate is what makes a restored certificate usable without
// contacting IMDS first, and is where MSAL .NET reads it from too.
func clientIDFromSubject(leaf *x509.Certificate) (string, bool) {
	cn := strings.TrimSpace(leaf.Subject.CommonName)
	if cn == "" {
		return "", false
	}
	// The common name is a GUID. Anything else is not a certificate this flow
	// issued, and sending it as a client ID would only produce a confusing
	// failure at the token endpoint.
	if !looksLikeGUID(cn) {
		return "", false
	}
	// Lowercased because the client ID read back here reaches a token-cache
	// partition key, and a certificate whose CN came back upper-cased would
	// otherwise land in a different partition than the same identity acquired
	// without the persisted certificate. MSAL .NET normalizes client IDs the
	// same way before they reach a cache key.
	return strings.ToLower(cn), true
}

func looksLikeGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

func (w windowsPersistentCertCache) write(alias string, cert *bindingCertificate) {
	if cert == nil || cert.Leaf == nil || len(cert.TLS.Certificate) == 0 {
		return
	}
	name, ok := encodeFriendlyName(alias, endpointBase(cert.Endpoint, cert.TenantID))
	if !ok {
		return
	}
	der := cert.TLS.Certificate[0]

	withAliasLock(alias, func() {
		store, err := openMyStore(false)
		if err != nil {
			return
		}
		defer func() { _ = windows.CertCloseStore(store, 0) }()

		contexts := snapshotStore(store)
		defer freeContexts(contexts)

		// Another process may have persisted a newer certificate for this
		// identity while this one was being issued. Overwriting it would
		// discard the better entry, so the write is skipped instead.
		nowUTC := now()
		var newest time.Time
		for _, ctx := range contexts {
			decoded, _, ok := decodeFriendlyName(friendlyName(ctx))
			if !ok || decoded != alias || !usesBindingKeyContainer(ctx) {
				continue
			}
			if _, leaf, ok := certificateFrom(ctx); ok && leaf.NotAfter.After(newest) {
				newest = leaf.NotAfter
			}
		}
		if !newest.IsZero() && !newest.Before(cert.Leaf.NotAfter) && newest.After(nowUTC) {
			return
		}

		if addCertificate(store, der, name) {
			pruneExpired(store, alias, nowUTC)
		}
	})
}

// addCertificate stores der under name and links it to the binding key.
func addCertificate(store windows.Handle, der []byte, name string) bool {
	// The length crosses into a uint32 parameter. A certificate this large is
	// not something the metadata service issues, so refusing is the honest
	// answer; truncating would hand crypt32 a length that does not describe the
	// buffer. The comparison goes through uint64 so it is also valid where int
	// is 32 bits.
	if len(der) == 0 || uint64(len(der)) > math.MaxUint32 {
		return false
	}
	// #nosec G115 -- the guard above bounds the length to uint32.
	ctx, err := windows.CertCreateCertificateContext(windows.X509_ASN_ENCODING, &der[0], uint32(len(der)))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CertFreeCertificateContext(ctx) }()

	var stored *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(
		store, ctx, windows.CERT_STORE_ADD_REPLACE_EXISTING, &stored,
	); err != nil || stored == nil {
		return false
	}
	defer func() { _ = windows.CertFreeCertificateContext(stored) }()

	// The properties go on the context the store handed back rather than the
	// one built from the bytes, because that is the one the store persists.
	if !setKeyProvInfo(stored) {
		// Without the container link the entry cannot be matched to a private
		// key, so it would be dead weight that the read path skips forever.
		_ = windows.CertDeleteCertificateFromStore(windows.CertDuplicateCertificateContext(stored))
		return false
	}
	if !setFriendlyName(stored, name) {
		_ = windows.CertDeleteCertificateFromStore(windows.CertDuplicateCertificateContext(stored))
		return false
	}
	return true
}

func setFriendlyName(ctx *windows.CertContext, name string) bool {
	encoded, err := windows.UTF16FromString(name)
	if err != nil {
		return false
	}
	// The byte count is twice the UTF-16 length and crosses into a uint32. A
	// friendly name is a short label, so anything approaching the limit is not
	// a name worth writing. The comparison goes through uint64 so it is also
	// valid where int is 32 bits.
	if len(encoded) == 0 || uint64(len(encoded)) > math.MaxUint32/2 {
		return false
	}
	blob := cryptDataBlob{
		// #nosec G115 -- the guard above bounds the byte count to uint32.
		cbData: uint32(len(encoded) * 2),
		pbData: (*byte)(unsafe.Pointer(&encoded[0])),
	}
	ret, _, _ := syscall.SyscallN(
		procCertSetCertificateContextProperty.Addr(),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(certFriendlyNamePropID),
		0,
		uintptr(unsafe.Pointer(&blob)),
	)
	return ret != 0
}

func setKeyProvInfo(ctx *windows.CertContext) bool {
	container, err := windows.UTF16PtrFromString(bindingKeyName)
	if err != nil {
		return false
	}
	provider, err := windows.UTF16PtrFromString(msKeyStorageProvider)
	if err != nil {
		return false
	}
	info := cryptKeyProvInfo{
		containerName: container,
		provName:      provider,
		keySpec:       certNCryptKeySpec,
	}
	ret, _, _ := syscall.SyscallN(
		procCertSetCertificateContextProperty.Addr(),
		uintptr(unsafe.Pointer(ctx)),
		uintptr(certKeyProvInfoPropID),
		0,
		uintptr(unsafe.Pointer(&info)),
	)
	return ret != 0
}

func (w windowsPersistentCertCache) deleteAll(alias string) {
	withAliasLock(alias, func() {
		store, err := openMyStore(false)
		if err != nil {
			return
		}
		defer func() { _ = windows.CertCloseStore(store, 0) }()
		deleteWhere(store, alias, func(*x509.Certificate) bool { return true })
	})
}

// pruneExpired removes entries for alias that are past their expiry, which is
// the conservative cleanup MSAL .NET performs after every write.
func pruneExpired(store windows.Handle, alias string, nowUTC time.Time) {
	deleteWhere(store, alias, func(leaf *x509.Certificate) bool {
		return !leaf.NotAfter.After(nowUTC)
	})
}

// deleteWhere removes every entry for alias that match accepts.
func deleteWhere(store windows.Handle, alias string, match func(*x509.Certificate) bool) {
	contexts := snapshotStore(store)
	var doomed []*windows.CertContext
	for _, ctx := range contexts {
		decoded, _, ok := decodeFriendlyName(friendlyName(ctx))
		if !ok || decoded != alias || !usesBindingKeyContainer(ctx) {
			continue
		}
		_, leaf, ok := certificateFrom(ctx)
		if !ok || !match(leaf) {
			continue
		}
		// The delete consumes the context, so the survivors and the doomed are
		// separated first and freed through different paths.
		doomed = append(doomed, ctx)
	}
	for _, ctx := range doomed {
		_ = windows.CertDeleteCertificateFromStore(ctx)
	}
	for _, ctx := range contexts {
		if !containsContext(doomed, ctx) {
			_ = windows.CertFreeCertificateContext(ctx)
		}
	}
}

func containsContext(list []*windows.CertContext, ctx *windows.CertContext) bool {
	for _, c := range list {
		if c == ctx {
			return true
		}
	}
	return false
}

// withAliasLock runs fn under a mutex shared by every process on the machine
// that persists certificates for this identity, so two of them cannot write the
// store at the same time.
//
// Global is tried first so the scope covers every session, including a service
// running alongside an interactive user. Creating a global object needs a
// privilege that is not always granted, and when it is refused the lock falls
// back to the session-local namespace: deduplicating within the session is
// worth more than not locking at all. Any other failure, including the lock
// simply being busy, skips the work rather than retrying, because persistence
// must never delay a token.
func withAliasLock(alias string, fn func()) {
	suffix := aliasLockSuffix(alias)
	if ok, denied := tryAliasLock(`Global\`+suffix, fn); ok || !denied {
		return
	}
	_, _ = tryAliasLock(`Local\`+suffix, fn)
}

func tryAliasLock(name string, fn func()) (ran bool, accessDenied bool) {
	encoded, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, false
	}
	handle, err := windows.CreateMutex(nil, false, encoded)
	if err != nil && handle == 0 {
		return false, err == windows.ERROR_ACCESS_DENIED
	}
	defer func() { _ = windows.CloseHandle(handle) }()

	event, err := windows.WaitForSingleObject(handle, uint32(persistLockTimeout/time.Millisecond))
	switch {
	case err != nil:
		return false, false
	case event == uint32(windows.WAIT_TIMEOUT):
		return false, false
	case event != windows.WAIT_OBJECT_0 && event != uint32(windows.WAIT_ABANDONED):
		// WAIT_ABANDONED means the previous holder died without releasing.
		// The lock is ours and the store is self-describing, so there is
		// nothing to recover and the work proceeds.
		return false, false
	}
	defer func() { _ = windows.ReleaseMutex(handle) }()
	fn()
	return true, false
}

// aliasLockSuffix derives a mutex name from the identity.
//
// The alias is hashed because it can contain characters a kernel object name
// cannot, and can be longer than the name limit. The scheme is MSAL .NET's, so
// both libraries take the same lock rather than each taking their own and
// writing the store concurrently.
func aliasLockSuffix(alias string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(alias))))
	return "MSAL_MI_P_" + hex.EncodeToString(sum[:])[:32]
}

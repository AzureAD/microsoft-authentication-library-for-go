// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//go:build !windows

package managedidentity

// newPlatformPersistentCertCache returns the persistent cache for this host.
//
// Persistence is Windows only, in both this library and MSAL .NET. The store
// entry has to carry the identity it was issued for, and the friendly name
// property that carries it is a Windows certificate store concept with no
// portable equivalent. There is also nothing to persist elsewhere: the binding
// key is a CNG key, so the IMDSv2 flow does not run on these platforms at all.
func newPlatformPersistentCertCache() persistentCertCache {
	return noopPersistentCertCache{}
}

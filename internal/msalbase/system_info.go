// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

import (
	"github.com/shirou/gopsutil/host"
)

// GetOSPlatform gets the OS that the client using MSAL is running on.
func GetOSPlatform() string {
	h, _ := host.Info()
	return h.Platform
}

// GetOSVersion gets the OS version that the client using MSAL is running on.
func GetOSVersion() string {
	h, _ := host.Info()
	return h.PlatformVersion
}

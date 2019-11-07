package msalbase

import (
	"github.com/shirou/gopsutil/host"
)

func GetOSPlatform() string {
	h, _ := host.Info()
	return h.Platform
}

func GetOSVersion() string {
	h, _ := host.Info()
	return h.PlatformVersion
}

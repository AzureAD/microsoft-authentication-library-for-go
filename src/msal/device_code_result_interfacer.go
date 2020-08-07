// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "time"

// DeviceCodeResultInterfacer is an interface for DeviceCodeResult that can be returned to users.
// You can use these functions to show the user different parameters of the device code result.
type DeviceCodeResultInterfacer interface {
	GetMessage() string
	String() string
	GetUserCode() string
	GetDeviceCode() string
	GetVerificationURL() string
	GetExpiresOn() time.Time
	GetInterval() int
}

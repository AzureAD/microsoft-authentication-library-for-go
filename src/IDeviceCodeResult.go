// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalgo

import "time"

// IDeviceCodeResult is an interface for DeviceCodeResult
type IDeviceCodeResult interface {
	GetMessage() string
	String() string
	GetUserCode() string
	GetDeviceCode() string
	GetVerificationURL() string
	GetExpiresOn() time.Time
	GetInterval() int
}

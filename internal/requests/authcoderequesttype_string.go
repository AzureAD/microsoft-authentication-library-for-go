// Code generated by "stringer -type=AuthCodeRequestType"; DO NOT EDIT.

package requests

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[UnknownAuthCodeType-0]
	_ = x[AuthCodePublic-1]
	_ = x[AuthCodeConfidential-2]
}

const _AuthCodeRequestType_name = "UnknownAuthCodeTypeAuthCodePublicAuthCodeConfidential"

var _AuthCodeRequestType_index = [...]uint8{0, 19, 33, 53}

func (i AuthCodeRequestType) String() string {
	if i < 0 || i >= AuthCodeRequestType(len(_AuthCodeRequestType_index)-1) {
		return "AuthCodeRequestType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _AuthCodeRequestType_name[_AuthCodeRequestType_index[i]:_AuthCodeRequestType_index[i+1]]
}

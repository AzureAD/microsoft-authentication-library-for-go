// Code generated by "stringer -type=AuthorizationType"; DO NOT EDIT.

package msalbase

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[AuthorizationTypeUnknown-0]
}

const _AuthorizationType_name = "AuthorizationTypeUnknown"

var _AuthorizationType_index = [...]uint8{0, 24}

func (i AuthorizationType) String() string {
	if i < 0 || i >= AuthorizationType(len(_AuthorizationType_index)-1) {
		return "AuthorizationType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _AuthorizationType_name[_AuthorizationType_index[i]:_AuthorizationType_index[i+1]]
}

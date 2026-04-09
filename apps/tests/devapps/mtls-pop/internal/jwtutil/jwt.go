// Package jwtutil provides shared JWT helpers for mTLS PoP manual test drivers.
package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// DecodeClaims decodes the JWT payload and returns (token_type, cnf) claims.
// Returns descriptive strings on error rather than failing.
func DecodeClaims(token string) (tokenType, cnf string) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "(not a JWT)", ""
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "(decode error)", ""
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return "(json error)", ""
	}
	if tt, ok := claims["token_type"].(string); ok {
		tokenType = tt
	} else {
		tokenType = "(not present)"
	}
	if c, ok := claims["cnf"]; ok {
		b, _ := json.Marshal(c)
		cnf = string(b)
	} else {
		cnf = "(not present)"
	}
	return
}

// Package jwtutil provides shared JWT helpers for mTLS PoP manual test drivers.
package jwtutil

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
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

// PrintTokenInfo prints common mTLS PoP token details: token preview, expiry,
// token source, and decoded JWT claims (token_type, cnf).
func PrintTokenInfo(accessToken string, expiresOn time.Time, tokenSource int) {
	tokenLen := len(accessToken)
	if tokenLen > 60 {
		tokenLen = 60
	}
	fmt.Printf("  Token (first 60 chars): %s...\n", accessToken[:tokenLen])
	fmt.Printf("  Expires:     %s\n", expiresOn)
	fmt.Printf("  TokenSource: %v\n", tokenSource)

	tokenType, cnf := DecodeClaims(accessToken)
	fmt.Printf("  token_type (JWT): %s\n", tokenType)
	fmt.Printf("  cnf claim (JWT):  %s\n", cnf)

	if tokenType == "mtls_pop" {
		fmt.Println("  ✅ Token type is mtls_pop")
	} else {
		fmt.Printf("  ⚠️  Token type is %q (expected mtls_pop)\n", tokenType)
	}
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package cache

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// TokenCache provides thread-safe token caching with auto-renewal
type TokenCache struct {
	mu            sync.RWMutex
	tokens        map[string]*CachedToken
	renewalBuffer time.Duration // How long before expiry to renew (default: 2 minutes)
}

// CachedToken represents a cached token with metadata
type CachedToken struct {
	Token     string
	ExpiresAt time.Time
	Scopes    []string
	TenantID  string
	CreatedAt time.Time
}

// NewTokenCache creates a new thread-safe token cache
func NewTokenCache(renewalBuffer time.Duration) *TokenCache {
	if renewalBuffer <= 0 {
		renewalBuffer = 2 * time.Minute // Default 2-minute buffer
	}
	return &TokenCache{
		tokens:        make(map[string]*CachedToken),
		renewalBuffer: renewalBuffer,
	}
}

// GetToken retrieves a valid token from cache, returns empty string if not found or expired
func (tc *TokenCache) GetToken(scopes []string, tenantID string) string {
	key := tc.generateKey(scopes, tenantID)

	tc.mu.RLock()
	cached, exists := tc.tokens[key]
	tc.mu.RUnlock()

	if !exists {
		return ""
	}

	// Check if token is still valid (with renewal buffer)
	if time.Now().Add(tc.renewalBuffer).After(cached.ExpiresAt) {
		// Token is expired or about to expire, remove it
		tc.mu.Lock()
		delete(tc.tokens, key)
		tc.mu.Unlock()
		return ""
	}

	return cached.Token
}

// GetCachedTokenData returns the full cached token data
func (tc *TokenCache) GetCachedTokenData(scopes []string, tenantID string) *CachedToken {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	key := tc.generateKey(scopes, tenantID)
	if data, exists := tc.tokens[key]; exists && data.ExpiresAt.After(time.Now()) {
		return data
	}
	return nil
}

// SetToken stores a token in the cache
func (tc *TokenCache) SetToken(scopes []string, tenantID, token string, expiresAt time.Time) {
	key := tc.generateKey(scopes, tenantID)

	tc.mu.Lock()
	tc.tokens[key] = &CachedToken{
		Token:     token,
		ExpiresAt: expiresAt,
		Scopes:    scopes,
		TenantID:  tenantID,
		CreatedAt: time.Now(),
	}
	tc.mu.Unlock()
}

// ClearToken removes a specific token from cache
func (tc *TokenCache) ClearToken(scopes []string, tenantID string) {
	key := tc.generateKey(scopes, tenantID)

	tc.mu.Lock()
	delete(tc.tokens, key)
	tc.mu.Unlock()
}

// ClearAll removes all tokens from cache
func (tc *TokenCache) ClearAll() {
	tc.mu.Lock()
	tc.tokens = make(map[string]*CachedToken)
	tc.mu.Unlock()
}

// IsTokenValid checks if a token exists and is valid
func (tc *TokenCache) IsTokenValid(scopes []string, tenantID string) bool {
	key := tc.generateKey(scopes, tenantID)

	tc.mu.RLock()
	cached, exists := tc.tokens[key]
	tc.mu.RUnlock()

	if !exists {
		return false
	}

	return time.Now().Add(tc.renewalBuffer).Before(cached.ExpiresAt)
}

// generateKey creates a unique key for the token cache
func (tc *TokenCache) generateKey(scopes []string, tenantID string) string {
	// Create a deterministic key from scopes and tenant
	scopeStr := strings.Join(scopes, ",")
	return fmt.Sprintf("%s|%s", tenantID, scopeStr)
}

// GetCacheStats returns statistics about the cache
func (tc *TokenCache) GetCacheStats() map[string]interface{} {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	now := time.Now()
	validCount := 0
	expiredCount := 0

	for _, token := range tc.tokens {
		if now.Add(tc.renewalBuffer).Before(token.ExpiresAt) {
			validCount++
		} else {
			expiredCount++
		}
	}

	return map[string]interface{}{
		"total_tokens":   len(tc.tokens),
		"valid_tokens":   validCount,
		"expired_tokens": expiredCount,
		"renewal_buffer": tc.renewalBuffer.String(),
	}
}

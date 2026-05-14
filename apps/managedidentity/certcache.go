// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"
)

type mtlsBindingInfo struct {
	tlsCert  tls.Certificate
	x509Cert *x509.Certificate
	endpoint string
	clientID string
	tenantID string
	expiresAt time.Time
}

type mtlsCertCache struct {
	mu    sync.RWMutex
	cache map[string]*mtlsBindingInfo
}

var globalMtlsCertCache = &mtlsCertCache{cache: make(map[string]*mtlsBindingInfo)}

// GetOrCreate returns a cached mtlsBindingInfo if it's still valid, otherwise calls factory to create a new one.
func (c *mtlsCertCache) GetOrCreate(ctx context.Context, key string, factory func(context.Context) (*mtlsBindingInfo, error)) (*mtlsBindingInfo, error) {
	c.mu.RLock()
	info, ok := c.cache[key]
	c.mu.RUnlock()

	if ok && time.Now().Before(info.expiresAt) {
		return info, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	info, ok = c.cache[key]
	if ok && time.Now().Before(info.expiresAt) {
		return info, nil
	}

	newInfo, err := factory(ctx)
	if err != nil {
		return nil, err
	}
	c.cache[key] = newInfo
	return newInfo, nil
}

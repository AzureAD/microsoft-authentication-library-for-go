// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package tokencache

import (
	"strconv"
	"testing"
	"time"
)

func TestIsAccessTokenValid(t *testing.T) {
	accessTokenCacheItem := CreateAccessTokenCacheItem(
		"hid",
		"env",
		"realm",
		"cid",
		time.Now().Unix(),
		time.Now().Unix()+1000,
		time.Now().Unix(),
		"openid",
		"secret",
	)
	validity := isAccessTokenValid(accessTokenCacheItem)
	if !validity {
		t.Errorf("Access token should be valid")
	}
	accessTokenCacheItem.ExpiresOnUnixTimestamp = strconv.FormatInt(time.Now().Unix()+200, 10)
	validity = isAccessTokenValid(accessTokenCacheItem)
	if validity {
		t.Errorf("Access token shouldn't be valid")
	}
	accessTokenCacheItem.ExpiresOnUnixTimestamp = "TIMESTAMP_SHOULD_BE_INT"
	validity = isAccessTokenValid(accessTokenCacheItem)
	if validity {
		t.Errorf("Access token shouldn't be valid")
	}
	accessTokenCacheItem.CachedAt = "TIMESTAMP_SHOULD_BE_INT"
	validity = isAccessTokenValid(accessTokenCacheItem)
	if validity {
		t.Errorf("Access token shouldn't be valid")
	}
	accessTokenCacheItem.CachedAt = strconv.FormatInt(time.Now().Unix()+500, 10)
	validity = isAccessTokenValid(accessTokenCacheItem)
	if validity {
		t.Errorf("Access token shouldn't be valid")
	}
}

package tokencache

type ICacheKeyGenerator interface {
	GetAccessTokenKey(accessTokenCacheItem) string
	GetRefreshTokenKey(refreshTokenCacheItem) string
	GetIDTokenKey(idTokenCacheItem) string
	GetAccountKey(accountCacheItem) string
}

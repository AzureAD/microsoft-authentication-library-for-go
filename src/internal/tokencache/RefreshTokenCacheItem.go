package tokencache

type refreshTokenCacheItem struct {
	HomeAccountID    string
	Environment      string
	RawClientInfo    string
	CredentialType   string
	ClientID         string
	Secret           string
	AdditionalFields map[string]interface{}
}

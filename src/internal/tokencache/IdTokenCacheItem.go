package tokencache

type idTokenCacheItem struct {
	HomeAccountID    string
	Environment      string
	RawClientInfo    string
	CredentialType   string
	ClientID         string
	Secret           string
	TenantID         string
	AdditionalFields map[string]interface{}
}

package msalbase

type CredentialType int

const (
	CredentialTypeOauth2RefreshToken CredentialType = iota
	CredentialTypeOauth2AccessToken
	CredentialTypeOidcIDToken
	CredentialTypeOther
)

type Credential struct {
	homeAccountID     string
	environment       string
	realm             string
	rawClientInfo     string
	credentialType    CredentialType
	clientID          string
	familyID          string
	secret            string
	scopes            string
	expiresOn         int64
	extendedExpiresOn int64
	cachedAt          int64
	additionalFields  map[string]interface{}
}

func CreateCredentialRefreshToken(
	homeAccountID string,
	environment string,
	clientID string,
	cachedAt int64,
	refreshToken string,
	additionalFieldsJSON string) *Credential {

	c := &Credential{
		homeAccountID: homeAccountID,
		environment:   environment,
		clientID:      clientID,
		cachedAt:      cachedAt,
		secret:        refreshToken,
	}
	return c
}

func CreateCredentialAccessToken(
	homeAccountID string,
	environment string,
	realm string,
	clientID string,
	target string,
	cachedAt int64,
	expiresOn int64,
	extendedExpiresOn int64,
	accessToken string,
	additionalFieldsJSON string) *Credential {

	c := &Credential{
		homeAccountID:     homeAccountID,
		environment:       environment,
		realm:             realm,
		clientID:          clientID,
		scopes:            target,
		cachedAt:          cachedAt,
		expiresOn:         expiresOn,
		extendedExpiresOn: extendedExpiresOn,
		secret:            accessToken,
	}
	return c
}

func CreateCredentialIdToken(
	homeAccountID string,
	environment string,
	realm string,
	clientID string,
	cachedAt int64,
	idTokenRaw string,
	additionalFieldsJSON string) *Credential {
	c := &Credential{
		homeAccountID: homeAccountID,
		environment:   environment,
		realm:         realm,
		clientID:      clientID,
		cachedAt:      cachedAt,
		secret:        idTokenRaw,
	}
	return c
}

func (c *Credential) GetExpiresOn() int64 {
	return c.expiresOn
}

func (c *Credential) GetSecret() string {
	return c.secret
}

func (c *Credential) GetScopes() string {
	return c.scopes
}

func (c *Credential) GetCredentialType() CredentialType {
	return c.credentialType
}

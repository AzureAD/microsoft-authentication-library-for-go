package msalbase

type Account struct {
}

func CreateAccount(homeAccountID string,
	environment string,
	realm string,
	localAccountID string,
	authorityType AuthorityType,
	preferredUsername string,
	givenName string,
	familyName string,
	middleName string,
	name string,
	alternativeID string,
	rawClientInfo string,
	additionalFieldsJSON string) *Account {
	a := &Account{}
	return a
}

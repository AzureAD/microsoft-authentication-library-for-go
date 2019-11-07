package requests

import (
	"github.com/markzuber/msalgo/internal/msalbase"
)

type RealmMetadata struct {
	webRequestManager       IWebRequestManager
	friendlyNameToCanonical map[string]string
}

func CreateRealmMetadata(webRequestManager IWebRequestManager) *RealmMetadata {
	meta := &RealmMetadata{webRequestManager, map[string]string{}}
	return meta
}

func (meta *RealmMetadata) QueryCanonicalRealmFromServer(authParameters *msalbase.AuthParametersInternal) (string, error) {
	// authorityFriendlyName := authParameters.GetAuthority()
	// authorityMapKey := strings.ToLower(fmt.Sprintf("%v/%v", authorityFriendlyName.GetEnvironment(), authorityFriendlyName.GetRealm()))

	// val := meta.friendlyNameToCanonical[authorityMapKey]
	// if val != "" {
	// 	return val, nil
	// }

	// configInfo, err := meta.webRequestManager.GetProviderConfigurationInformation(authParameters)
	// if err != nil {
	// 	return "", err
	// }

	// // todo: create/validate that config.AuthorizationEndpoint is URI parseable

	// canonicalRealm := authEndpoint.GetRealm()
	// meta.friendlyNameToCanonical[authorityMapKey] = canonicalRealm
	// return canonicalRealm, nil

	return "this is a broken realm, not implemented", nil
}

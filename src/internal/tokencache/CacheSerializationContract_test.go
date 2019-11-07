package tokencache

import (
	"fmt"
	"testing"
)

func Test_cacheSerializationContract_MarshalJSON(t *testing.T) {

	contract := createCacheSerializationContract()
	atItem := &accessTokenCacheItem{}
	atItem.HomeAccountID = "this is a home account id"
	contract.AccessTokens["atkey"] = atItem

	bytes, err := contract.MarshalJSON()
	if err != nil {
		t.Errorf("cacheSerializationContract.MarshalJSON() error = %v", err)
		return
	}

	str := string(bytes)

	t.Logf(str)

	otherContract := createCacheSerializationContract()
	err = otherContract.UnmarshalJSON(bytes)
	if err != nil {
		t.Errorf("cacheSerializationContract.MarshalJSON() error = %v", err)
		return
	}

	str = fmt.Sprintf("%#v", otherContract)
	t.Log(str)
}

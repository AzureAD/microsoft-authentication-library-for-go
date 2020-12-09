package msalbase

import (
	"errors"
	"reflect"
	"testing"
)

func TestCreateOAuthResponseBase(t *testing.T) {
	const (
		oauthResponse          = `{}`
		oauthResponseWithError = `{"error" : "invalid request", "error_description": "missing payload content", "error_codes" : [300]}`
	)

	_, err := CreateOAuthResponseBase(404, []byte(oauthResponse))
	actualError := errors.New("HTTP 404")
	if err.Error() != actualError.Error() {
		t.Errorf("Actual error %v differs from expected error %v", err, actualError)
	}
	_, err = CreateOAuthResponseBase(300, []byte(oauthResponseWithError))
	if err == nil {
		t.Error("Unexpected nil error")
	}
	_, err = CreateOAuthResponseBase(200, []byte(oauthResponse))
	if err != nil {
		t.Errorf("Error should be nil, but it is %v", err)
	}
}

func TestConcatenateScopes(t *testing.T) {
	expectedScopes := "profile openid user.read"
	actualScopes := ConcatenateScopes([]string{"profile", "openid", "user.read"})
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Expected scopes %s differ from actual scopes %s", expectedScopes, actualScopes)
	}
}

func TestSplitScopes(t *testing.T) {
	expectedScopes := []string{"profile", "openid", "user.read"}
	actualScopes := SplitScopes("profile openid user.read")
	if !reflect.DeepEqual(expectedScopes, actualScopes) {
		t.Errorf("Expected scopes %v differ from actual scopes %v", expectedScopes, actualScopes)
	}
}

func TestDecodeJWT(t *testing.T) {
	encodedStr := "aGVsbG8"
	expectedStr := []byte("hello")
	actualString, err := DecodeJWT(encodedStr)
	if err != nil {
		t.Errorf("Error should be nil but it is %v", err)
	}
	if !reflect.DeepEqual(expectedStr, actualString) {
		t.Errorf("Actual decoded string %s differs from expected decoded string %s", actualString, expectedStr)
	}
}

func TestGetLocalAccountID(t *testing.T) {
	id := &IDToken{
		Subject: "sub",
	}
	actualLID := id.GetLocalAccountID()
	if !reflect.DeepEqual("sub", actualLID) {
		t.Errorf("Expected local account ID sub differs from actual local account ID %s", actualLID)
	}
	id.Oid = "oid"
	actualLID = id.GetLocalAccountID()
	if !reflect.DeepEqual("oid", actualLID) {
		t.Errorf("Expected local account ID oid differs from actual local account ID %s", actualLID)
	}
}

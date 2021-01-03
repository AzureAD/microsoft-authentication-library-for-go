// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

var (
	accHID   = "hid"
	accEnv   = "env"
	accRealm = "realm"
	authType = "MSSTS"
	accLid   = "lid"
	accUser  = "user"
)

var testRealm = `{"account_type" : "Federated",
					"domain_name" : "domain",
					"cloud_instance_name" : "cloud",
					"cloud_audience_urn" : "urn",
					"federation_protocol" : "fed_prot",
					"federation_metadata_url" : "fed_meta"}`

type fakeJSONCaller struct {
	err bool

	gotEndpoint string
	gotHeaders  http.Header
	gotQV       url.Values
	gotBody     interface{}
	gotResp     interface{}
}

func (f *fakeJSONCaller) JSONCall(ctx context.Context, endpoint string, headers http.Header, qv url.Values, body, resp interface{}) error {
	if f.err {
		return errors.New("error")
	}
	f.gotEndpoint = endpoint
	f.gotHeaders = headers
	f.gotQV = qv
	f.gotBody = body
	f.gotResp = resp

	return nil
}

func (f *fakeJSONCaller) compare(endpoint string, headers http.Header, qv url.Values, body, resp interface{}) error {
	if f.gotEndpoint != endpoint {
		return fmt.Errorf("got endpoint == %s, want endpoint == %s", f.gotEndpoint, endpoint)
	}
	if diff := pretty.Compare(headers, f.gotHeaders); diff != "" {
		return fmt.Errorf("headers -want/+got:\n%s", diff)
	}
	if diff := pretty.Compare(qv, f.gotQV); diff != "" {
		return fmt.Errorf("qv -want/+got:\n%s", diff)
	}
	if diff := pretty.Compare(body, f.gotBody); diff != "" {
		return fmt.Errorf("body -want/+got:\n%s", diff)
	}
	gotValue := reflect.ValueOf(f.gotResp)
	if gotValue.Kind() != reflect.Ptr {
		return fmt.Errorf("resp cannot be a non-pointer type")
	}
	gotValue = gotValue.Elem()

	gotName := gotValue.Type().Name()
	wantName := reflect.ValueOf(resp).Elem().Type().Name()

	if gotName != wantName {
		return fmt.Errorf("resp type was %s, want %s", gotName, wantName)
	}
	return nil
}

var testAuthorityEndpoints = NewEndpoints(
	"https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com",
)

func TestGetUserRealm(t *testing.T) {
	authParams := AuthParams{
		Username:      "username",
		Endpoints:     testAuthorityEndpoints,
		CorrelationID: "id",
	}

	tests := []struct {
		desc     string
		err      bool
		endpoint string
		headers  http.Header
		resp     interface{}
	}{
		{
			desc: "Error: comm returns error",
			err:  true,
		},
		{
			desc:     "Success",
			endpoint: authParams.Endpoints.UserRealmEndpoint(authParams.Username),
			headers:  http.Header{"client-request-id": []string{"id"}},
			resp:     &UserRealm{},
		},
	}

	for _, test := range tests {
		fake := &fakeJSONCaller{err: test.err}
		client := Client{fake}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetUserRealm(context.Background(), authParams)
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetUserRealm(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetUserRealm(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(test.endpoint, test.headers, nil, nil, test.resp); err != nil {
			t.Errorf("TestGetUserRealm(%s): %s", test.desc, err)
		}
	}
}

func TestGetTenantDiscoveryResponse(t *testing.T) {
	tests := []struct {
		desc     string
		err      bool
		endpoint string
		resp     interface{}
	}{
		{
			desc: "Error: comm returns error",
			err:  true,
		},
		{
			desc:     "Success",
			endpoint: "endpoint",
			resp:     &TenantDiscoveryResponse{},
		},
	}

	for _, test := range tests {
		fake := &fakeJSONCaller{err: test.err}
		client := Client{fake}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetTenantDiscoveryResponse(context.Background(), "endpoint")
		switch {
		case err == nil && test.err:
			t.Errorf("TestGetTenantDiscoveryResponse(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestGetTenantDiscoveryResponse(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(test.endpoint, http.Header{}, nil, nil, test.resp); err != nil {
			t.Errorf("TestGetTenantDiscoveryResponse(%s): %s", test.desc, err)
		}
	}
}

func TestGetAadinstanceDiscoveryResponse(t *testing.T) {
	tests := []struct {
		desc     string
		err      bool
		authInfo Info
		endpoint string
		qv       url.Values
		resp     interface{}
	}{
		{
			desc: "Error: comm returns error",
			err:  true,
		},
		{
			desc:     "Success with authorityInfo.Host not in trusted list",
			endpoint: fmt.Sprintf(instanceDiscoveryEndpoint, defaultHost),
			authInfo: Info{
				Host:   "host",
				Tenant: "tenant",
			},
			qv: url.Values{
				"api-version":            []string{"1.1"},
				"authorization_endpoint": []string{fmt.Sprintf(authorizationEndpoint, "host", "tenant")},
			},
			resp: &InstanceDiscoveryResponse{},
		},
		{
			desc:     "Success with authorityInfo.Host in trusted list",
			endpoint: fmt.Sprintf(instanceDiscoveryEndpoint, "login.microsoftonline.de"),
			authInfo: Info{
				Host:   "login.microsoftonline.de",
				Tenant: "tenant",
			},
			qv: url.Values{
				"api-version":            []string{"1.1"},
				"authorization_endpoint": []string{fmt.Sprintf(authorizationEndpoint, "login.microsoftonline.de", "tenant")},
			},
			resp: &InstanceDiscoveryResponse{},
		},
	}

	for _, test := range tests {
		fake := &fakeJSONCaller{err: test.err}
		client := Client{fake}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.GetAadinstanceDiscoveryResponse(context.Background(), test.authInfo)
		switch {
		case err == nil && test.err:
			t.Errorf("GetAadinstanceDiscoveryResponse(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("GetAadinstanceDiscoveryResponse(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(test.endpoint, http.Header{}, test.qv, nil, test.resp); err != nil {
			t.Errorf("GetAadinstanceDiscoveryResponse(%s): %s", test.desc, err)
		}
	}
}

func TestCreateAuthorityInfoFromAuthorityUri(t *testing.T) {
	const authorityURI = "https://login.microsoftonline.com/common/"

	want := Info{
		Host:                  "login.microsoftonline.com",
		CanonicalAuthorityURI: authorityURI,
		AuthorityType:         authType,
		UserRealmURIPrefix:    "https://login.microsoftonline.com/common/userrealm/",
		Tenant:                "common",
		ValidateAuthority:     true,
	}
	got, err := NewInfoFromAuthorityURI(authorityURI, true)
	if err != nil {
		t.Fatalf("TestCreateAuthorityInfoFromAuthorityUri: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestCreateAuthorityInfoFromAuthorityUri: -want/+got:\n%s", diff)
	}
}

func TestCreateUserRealm(t *testing.T) {
	// TODO(jdoak): make these maps that we just json.Marshal before we
	// call NewUserRealm().
	fedProtRealm := `{"account_type" : "Federated",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn",
				"federation_metadata_url" : "fed_meta"}`
	fedMetaRealm := `{"account_type" : "Federated",
				"domain_name" : "domain",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn",
				"federation_protocol" : "fed_prot"}`
	domainRealm := `{"account_type" : "Managed",
				"cloud_instance_name" : "cloud",
				"cloud_audience_urn" : "urn"}`
	cloudNameRealm := `{"account_type" : "Managed",
						"domain_name" : "domain",
						"cloud_audience_urn" : "urn"}`
	cloudURNRealm := `{"account_type" : "Managed",
						"domain_name" : "domain",
						"cloud_instance_name" : "cloud"}`

	tests := []struct {
		desc  string
		input string
		want  UserRealm
		err   bool
	}{
		{
			desc:  "success",
			input: testRealm,
			want: UserRealm{
				AccountType:           "Federated",
				DomainName:            "domain",
				CloudInstanceName:     "cloud",
				CloudAudienceURN:      "urn",
				FederationProtocol:    "fed_prot",
				FederationMetadataURL: "fed_meta",
			},
		},
		{desc: "error: Fed Protocol Realm", input: fedProtRealm, err: true},
		{desc: "error: Fed Meta Realm", input: fedMetaRealm, err: true},
		{desc: "error: Domain Realm", input: domainRealm, err: true},
		{desc: "error: Cloud Name Realm", input: cloudNameRealm, err: true},
		{desc: "error: Cloud URN Realm", input: cloudURNRealm, err: true},
	}
	for _, test := range tests {
		got, err := NewUserRealm(createFakeResp(http.StatusOK, test.input))
		switch {
		case err == nil && test.err:
			t.Errorf("TestCreateUserRealm(%s): got err == nil, want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestCreateUserRealm(%s): got err == %s, want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if diff := pretty.Compare(test.want, got); diff != "" {
			t.Errorf("TestCreateUserRealm(%s): -want/+got:\n%s", test.desc, diff)
		}
	}
}

func createFakeResp(code int, body string) *http.Response {
	return &http.Response{
		Body:       ioutil.NopCloser(strings.NewReader(body)),
		StatusCode: code,
	}
}

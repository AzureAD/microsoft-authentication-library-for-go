// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package authority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"testing"

	"github.com/kylelemons/godebug/pretty"
)

type fakeJSONCaller struct {
	err bool

	resp []byte

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

	if f.resp != nil {
		if err := json.Unmarshal(f.resp, resp); err != nil {
			return err
		}
	}

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

func TestUserRealm(t *testing.T) {
	authParams := AuthParams{
		Username:      "username",
		Endpoints:     testAuthorityEndpoints,
		CorrelationID: "id",
	}

	tests := []struct {
		desc     string
		err      bool
		endpoint string
		jsonResp *UserRealm
		headers  http.Header
		qv       url.Values
		resp     interface{}
	}{
		{
			desc: "Error: comm returns error",
			err:  true,
		},
		{
			desc:     "Success",
			endpoint: fmt.Sprintf("https://login.microsoftonline.com/common/UserRealm/%s", url.PathEscape(authParams.Username)),
			headers: http.Header{
				"client-request-id": []string{"id"},
			},
			qv: url.Values{
				"api-version": []string{"1.0"},
			},
			jsonResp: &UserRealm{
				AccountType:       "Managed",
				DomainName:        "microsoftonline.com",
				CloudInstanceName: "instance",
				CloudAudienceURN:  "urn",
			},
			resp: &UserRealm{},
		},
	}

	for _, test := range tests {
		fake := &fakeJSONCaller{err: test.err}
		client := Client{fake}
		if test.jsonResp != nil {
			b, err := json.Marshal(test.jsonResp)
			if err != nil {
				panic(err)
			}
			fake.resp = b
		}

		// We don't care about the result, that is just a translation from the JSON handled
		// automatically in the comm package.  We care only that the comm package got what
		// it needed.
		_, err := client.UserRealm(context.Background(), authParams)
		switch {
		case err == nil && test.err:
			t.Errorf("TestUserRealm(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestUserRealm(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(test.endpoint, test.headers, test.qv, nil, test.resp); err != nil {
			t.Errorf("TestUserRealm(%s): %s", test.desc, err)
		}
	}
}

func TestTenantDiscoveryResponse(t *testing.T) {
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
			t.Errorf("TestTenantDiscoveryResponse(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestTenantDiscoveryResponse(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(test.endpoint, http.Header{}, nil, nil, test.resp); err != nil {
			t.Errorf("TestTenantDiscoveryResponse(%s): %s", test.desc, err)
		}
	}
}

func TestAADInstanceDiscovery(t *testing.T) {
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
		_, err := client.AADInstanceDiscovery(context.Background(), test.authInfo)
		switch {
		case err == nil && test.err:
			t.Errorf("AADInstanceDiscovery(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("AADInstanceDiscovery(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compare(test.endpoint, http.Header{}, test.qv, nil, test.resp); err != nil {
			t.Errorf("AADInstanceDiscovery(%s): %s", test.desc, err)
		}
	}
}

func TestAADInstanceDiscoveryWithRegion(t *testing.T) {
	fake := &fakeJSONCaller{}
	client := Client{fake}
	authInfo := Info{
		Host:   "host",
		Tenant: "tenant",
		Region: "eastus",
	}
	resp, err := client.AADInstanceDiscovery(context.Background(), authInfo)
	if err != nil {
		t.Errorf("AADInstanceDiscoveryWithRegion failing with %s", err)
	}
	expectedTenantDiscoveryEndpoint := fmt.Sprintf(TenantDiscoveryEndpointWithRegion, "eastus", "host", "tenant")
	expectedPreferredNetwork := fmt.Sprintf("%v.%v", "eastus", "host")
	expectedPreferredCache := "host"
	if resp.TenantDiscoveryEndpoint != expectedTenantDiscoveryEndpoint {
		t.Errorf("AADInstanceDiscoveryWithRegion incorrect TenantDiscoveryEndpoint: got: %s , want: %s", resp.TenantDiscoveryEndpoint, expectedTenantDiscoveryEndpoint)
	}
	if resp.Metadata[0].PreferredNetwork != expectedPreferredNetwork {
		t.Errorf("AADInstanceDiscoveryWithRegion incorrect Preferred Network got: %s , want: %s", resp.Metadata[0].PreferredNetwork, expectedPreferredNetwork)
	}
	if resp.Metadata[0].PreferredCache != expectedPreferredCache {
		t.Errorf("AADInstanceDiscoveryWithRegion incorrect Preferred Cache got: %s , want: %s", resp.Metadata[0].PreferredCache, expectedPreferredCache)

	}
}
func TestCreateAuthorityInfoFromAuthorityUri(t *testing.T) {
	const authorityURI = "https://login.microsoftonline.com/common/"

	want := Info{
		Host:                  "login.microsoftonline.com",
		CanonicalAuthorityURI: authorityURI,
		AuthorityType:         "MSSTS",
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

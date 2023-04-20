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
	"strings"
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
	client := Client{&fakeJSONCaller{}}
	region := "region"
	discoveryPath := "tenant/v2.0/.well-known/openid-configuration"
	publicCloudEndpoint := fmt.Sprintf("https://%s.login.microsoft.com/%s", region, discoveryPath)
	for _, test := range []struct{ host, expectedEndpoint string }{
		{"login.chinacloudapi.cn", fmt.Sprintf("https://%s.login.chinacloudapi.cn/%s", region, discoveryPath)},
		{"login.microsoft.com", publicCloudEndpoint},
		{"login.microsoftonline.com", publicCloudEndpoint},
		{"login.windows.net", publicCloudEndpoint},
		{"login.windows-ppe.net", fmt.Sprintf("https://%s.login.windows-ppe.net/%s", region, discoveryPath)},
		{"sts.windows.net", publicCloudEndpoint},
	} {
		t.Run(test.host, func(t *testing.T) {
			authInfo := Info{Host: test.host, Tenant: "tenant", Region: region}
			resp, err := client.AADInstanceDiscovery(context.Background(), authInfo)
			if err != nil {
				t.Errorf("AADInstanceDiscoveryWithRegion failing with %s", err)
			}
			expectedPreferredNetwork := fmt.Sprintf("%v.%v", region, test.host)
			expectedPreferredCache := test.host
			if resp.TenantDiscoveryEndpoint != test.expectedEndpoint {
				t.Errorf("AADInstanceDiscoveryWithRegion incorrect TenantDiscoveryEndpoint: got: %s, want: %s", resp.TenantDiscoveryEndpoint, test.expectedEndpoint)
			}
			if resp.Metadata[0].PreferredNetwork != expectedPreferredNetwork {
				t.Errorf("AADInstanceDiscoveryWithRegion incorrect Preferred Network got: %s, want: %s", resp.Metadata[0].PreferredNetwork, expectedPreferredNetwork)
			}
			if resp.Metadata[0].PreferredCache != expectedPreferredCache {
				t.Errorf("AADInstanceDiscoveryWithRegion incorrect Preferred Cache got: %s, want: %s", resp.Metadata[0].PreferredCache, expectedPreferredCache)

			}
		})
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
	got, err := NewInfoFromAuthorityURI(authorityURI, true, false)
	if err != nil {
		t.Fatalf("TestCreateAuthorityInfoFromAuthorityUri: got err == %s, want err == nil", err)
	}

	if diff := pretty.Compare(want, got); diff != "" {
		t.Errorf("TestCreateAuthorityInfoFromAuthorityUri: -want/+got:\n%s", diff)
	}
}

func TestAuthParamsWithTenant(t *testing.T) {
	uuid1 := "00000000-0000-0000-0000-000000000000"
	uuid2 := strings.ReplaceAll(uuid1, "0", "1")
	host := "https://localhost/"
	for _, test := range []struct {
		authority, expectedAuthority, tenant string
		expectError                          bool
	}{
		{authority: host + "common", tenant: uuid1, expectedAuthority: host + uuid1},
		{authority: host + "organizations", tenant: uuid1, expectedAuthority: host + uuid1},
		{authority: host + uuid1, tenant: uuid2, expectedAuthority: host + uuid2},
		{authority: host + uuid1, tenant: "common", expectError: true},
		{authority: host + uuid1, tenant: "organizations", expectError: true},
		{authority: host + "adfs", tenant: uuid1, expectError: true},
		{authority: host + "consumers", tenant: uuid1, expectError: true},
	} {
		t.Run("", func(t *testing.T) {
			info, err := NewInfoFromAuthorityURI(test.authority, false, false)
			if err != nil {
				t.Fatal(err)
			}
			params := NewAuthParams("client-id", info)
			p, err := params.WithTenant(test.tenant)
			if test.expectError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			if v := strings.TrimSuffix(p.AuthorityInfo.CanonicalAuthorityURI, "/"); v != test.expectedAuthority {
				t.Fatalf(`unexpected tenant "%s"`, v)
			}
		})
	}

	// WithTenant shouldn't change AuthorityInfo fields unrelated to the tenant, such as Region
	t.Run("AuthorityInfo", func(t *testing.T) {
		a := "A"
		b := "B"
		before, err := NewInfoFromAuthorityURI("https://localhost/"+a, true, false)
		if err != nil {
			t.Fatal(err)
		}
		before.Region = "region"
		params := NewAuthParams("client-id", before)
		p, err := params.WithTenant(b)
		if err != nil {
			t.Fatal(err)
		}
		after := p.AuthorityInfo

		// these values should be different because they contain the tenant (this is tested above)
		after.CanonicalAuthorityURI = before.CanonicalAuthorityURI
		after.Tenant = before.Tenant
		// With those fields equal, we can compare the before and after Infos without enumerating
		// their fields i.e., we can implicitly compare all the other fields at once. With this
		// approach, when Info gets a new field, this test needs an update only if that field
		// contains the tenant, in which case this test will break so maintainers don't overlook it.
		if diff := pretty.Compare(before, after); diff != "" {
			t.Fatal(diff)
		}
	})
}

func TestMergeCapabilitiesAndClaims(t *testing.T) {
	for _, test := range []struct {
		capabilities              []string
		challenge, desc, expected string
		err                       bool
	}{
		{
			desc:     "no capabilities or challenge",
			expected: "",
		},
		{
			desc:         "encoded challenge",
			capabilities: []string{"cp1"},
			challenge:    "eyJpZF90b2tlbiI6eyJhdXRoX3RpbWUiOnsiZXNzZW50aWFsIjp0cnVlfX19",
			err:          true,
		},
		{
			desc:         "only capabilities",
			capabilities: []string{"cp1"},
			expected:     `{"access_token":{"xms_cc":{"values":["cp1"]}}}`,
		},
		{
			desc:      "only challenge",
			challenge: `{"id_token":{"auth_time":{"essential":true}}}`,
			expected:  `{"id_token":{"auth_time":{"essential":true}}}`,
		},
		{
			desc:         "overlapping claim", // i.e. capabilities and claims are siblings
			capabilities: []string{"cp1", "cp2"},
			challenge:    `{"access_token":{"nbf":{"essential":true, "value":"42"}}}`,
			expected:     `{"access_token":{"nbf":{"essential":true, "value":"42"}, "xms_cc":{"values":["cp1","cp2"]}}}`,
		},
		{
			desc:         "non-overlapping claim",
			capabilities: []string{"cp1", "cp2"},
			challenge:    `{"id_token":{"auth_time":{"essential":true}}}`,
			expected:     `{"id_token":{"auth_time":{"essential":true}}, "access_token":{"xms_cc":{"values":["cp1","cp2"]}}}`,
		},
		{
			desc:         "overlapping and non-overlapping claims",
			capabilities: []string{"cp1", "cp2"},
			challenge:    `{"id_token":{"auth_time":{"essential":true}},"access_token":{"nbf":{"essential":true, "value":"42"}}}`,
			expected:     `{"id_token":{"auth_time":{"essential":true}},"access_token":{"nbf":{"essential":true, "value":"42"},"xms_cc":{"values":["cp1","cp2"]}}}`,
		},
	} {
		cpb, err := NewClientCapabilities(test.capabilities)
		if err != nil {
			t.Fatal(err)
		}
		ap := AuthParams{Capabilities: cpb, Claims: test.challenge}
		t.Run(test.desc, func(t *testing.T) {
			var expected map[string]any
			if err := json.Unmarshal([]byte(test.expected), &expected); err != nil && test.expected != "" {
				t.Fatal("test bug: the expected result must be JSON or an empty string")
			}
			merged, err := ap.MergeCapabilitiesAndClaims()
			if err != nil {
				if test.err {
					return
				}
				t.Fatal(err)
			}
			if merged == test.expected {
				return
			}
			var actual map[string]any
			if err = json.Unmarshal([]byte(merged), &actual); err != nil {
				t.Fatal(err)
			}
			if diff := pretty.Compare(expected, actual); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

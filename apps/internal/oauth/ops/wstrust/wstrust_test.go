// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust/defs"
	"github.com/kylelemons/godebug/diff"
	"github.com/kylelemons/godebug/pretty"
)

var testAuthorityEndpoints = authority.NewEndpoints(
	"https://login.microsoftonline.com/v2.0/authorize",
	"https://login.microsoftonline.com/v2.0/token",
	"https://login.microsoftonline.com/v2.0",
	"login.microsoftonline.com",
)

type fakeXMLCaller struct {
	err      bool
	giveResp interface{}

	gotAction   string
	gotEndpoint string
	gotQV       url.Values
	gotHeaders  http.Header
	gotBody     interface{}
	gotResp     interface{}
}

func (f *fakeXMLCaller) XMLCall(ctx context.Context, endpoint string, headers http.Header, qv url.Values, resp interface{}) error {
	if f.err {
		return errors.New("error")
	}
	f.gotEndpoint = endpoint
	f.gotHeaders = headers
	f.gotQV = qv
	f.gotResp = resp
	return nil
}

func (f *fakeXMLCaller) SOAPCall(ctx context.Context, endpoint, action string, headers http.Header, qv url.Values, body string, resp interface{}) error {
	if f.err {
		return errors.New("error")
	}
	f.gotEndpoint = endpoint
	f.gotAction = action
	f.gotHeaders = headers
	f.gotQV = qv
	f.gotBody = body
	f.gotResp = resp

	if f.giveResp != nil {
		b, err := xml.MarshalIndent(f.giveResp, "", "\t")
		if err != nil {
			panic(err)
		}

		if err := xml.Unmarshal(b, resp); err != nil {
			panic(err)
		}
	}

	return nil
}

func (f *fakeXMLCaller) compareBase(endpoint string, headers http.Header, qv url.Values, resp interface{}) error {
	if f.gotEndpoint != endpoint {
		return fmt.Errorf("got endpoint == %s, want endpoint == %s", f.gotEndpoint, endpoint)
	}
	if diff := pretty.Compare(headers, f.gotHeaders); diff != "" {
		return fmt.Errorf("headers -want/+got:\n%s", diff)
	}
	if diff := pretty.Compare(qv, f.gotQV); diff != "" {
		return fmt.Errorf("qv -want/+got:\n%s", diff)
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

func (f *fakeXMLCaller) compareXML(endpoint string, resp interface{}) error {
	if err := f.compareBase(endpoint, http.Header{}, url.Values{}, resp); err != nil {
		return err
	}

	return nil
}

var replaceURNRE = regexp.MustCompile(`urn:uuid:.*</was:messageID>`)

func (f *fakeXMLCaller) compareSOAP(action, endpoint string, body, resp interface{}) error {
	if err := f.compareBase(endpoint, http.Header{}, nil, resp); err != nil {
		return err
	}

	if f.gotAction != action {
		return fmt.Errorf("got endpoint == %s, want endpoint == %s", f.gotEndpoint, endpoint)
	}

	// Removes a uuid that will change every time.
	// example: `urn:uuid:373ea2fa-d586-4cad-8bb8-10392ddbb5c6</wsa:messageID>``
	bodyStr := replaceURNRE.ReplaceAllString(body.(string), `</was:messageID>`)
	gotBodyStr := replaceURNRE.ReplaceAllString(body.(string), `</was:messageID>`)

	if diff := diff.Diff(
		strings.ReplaceAll(bodyStr, ">", ">\n"),    // So we can do a line by line comparison
		strings.ReplaceAll(gotBodyStr, ">", ">\n"), // So we can do a line by line comparison
	); diff != "" {
		return fmt.Errorf("body -want/+got:\n%s", diff)
	}
	return nil
}

func TestMex(t *testing.T) {
	tests := []struct {
		desc                  string
		err                   bool
		createErr             bool
		newFromDef            func(d defs.Definitions) (defs.MexDocument, error)
		federationMetadataURL string
	}{
		{
			desc: "Error: comm returns error",
			err:  true,
		},
		{
			desc:                  "Definition was bad",
			federationMetadataURL: "",
			newFromDef: func(d defs.Definitions) (defs.MexDocument, error) {
				return defs.MexDocument{}, errors.New("error")
			},
			err: true,
		},
		{
			desc:                  "Success",
			federationMetadataURL: "",
			newFromDef: func(d defs.Definitions) (defs.MexDocument, error) {
				return defs.MexDocument{}, nil
			},
		},
	}

	defer func() { newFromDef = defs.NewFromDef }()

	for _, test := range tests {
		newFromDef = test.newFromDef

		fake := &fakeXMLCaller{err: test.err}
		client := Client{Comm: fake}

		// We don't care about the result, that is just a translation from the XML handled
		// in the comm package via wstrust.CreateWsTrustMexDocumentFromDef().
		// We care only that the comm package got what the right inputs.
		_, err := client.Mex(context.Background(), "http://something")
		switch {
		case err == nil && test.err:
			t.Errorf("TestMex(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestMex(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compareXML("http://something", &defs.Definitions{}); err != nil {
			t.Errorf("TestMex(%s): %s", test.desc, err)
		}
	}
}

func TestSAMLTokenInfo(t *testing.T) {
	authParams := authority.AuthParams{
		Username:  "username",
		Password:  "password",
		Endpoints: testAuthorityEndpoints,
		ClientID:  "clientID",
	}

	// Note: We don't tests any error conditions built on buildTokenRequestMessage(),
	// as they can only fail if the xml marshaller fails.
	tests := []struct {
		desc              string
		err               bool
		commErr           bool
		endpoint          defs.Endpoint
		body              string
		action            string
		authorizationType authority.AuthorizeType
		giveResp          defs.SAMLDefinitions
	}{
		{
			desc:              "Error: comm returns error",
			err:               true,
			commErr:           true,
			endpoint:          defs.Endpoint{Version: defs.Trust13, URL: "upEndpoint"},
			action:            SoapActionDefault,
			authorizationType: authority.ATWindowsIntegrated,
			body:              "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><s:Header><wsa:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action><wsa:messageID>urn:uuid:fb8ec65b-f117-468f-b4e8-50c5e802affe</wsa:messageID><wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo><wsa:To s:mustUnderstand=\"1\">upEndpoint</wsa:To><wsse:Security s:mustUnderstand=\"\" xmlns:wsse=\"\"><wsu:Timestamp wsu:Id=\"\"><wsu:Created></wsu:Created><wsu:Expires></wsu:Expires></wsu:Timestamp><wsse:UsernameToken wsu:Id=\"\"><wsse:Username></wsse:Username><wsse:Password></wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference><wsa:Address>urn</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType></wst:RequestSecurityToken></s:Body></s:Envelope>",
			giveResp: defs.SAMLDefinitions{
				Body: defs.Body{
					RequestSecurityTokenResponseCollection: defs.RequestSecurityTokenResponseCollection{
						RequestSecurityTokenResponse: []defs.RequestSecurityTokenResponse{
							{
								RequestedSecurityToken: defs.RequestedSecurityToken{
									Assertion: defs.Assertion{
										Text: "hello",
										XMLName: xml.Name{
											Local: "Assertion",
										},
										Saml: samlv1Assertion,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc:              "Error: Trust2005 endpoint, which isn't supported",
			err:               true,
			endpoint:          defs.Endpoint{Version: defs.Trust2005, URL: "upEndpoint"},
			action:            SoapActionDefault,
			authorizationType: authority.ATWindowsIntegrated,
			body:              "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><s:Header><wsa:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action><wsa:messageID>urn:uuid:fb8ec65b-f117-468f-b4e8-50c5e802affe</wsa:messageID><wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo><wsa:To s:mustUnderstand=\"1\">upEndpoint</wsa:To><wsse:Security s:mustUnderstand=\"\" xmlns:wsse=\"\"><wsu:Timestamp wsu:Id=\"\"><wsu:Created></wsu:Created><wsu:Expires></wsu:Expires></wsu:Timestamp><wsse:UsernameToken wsu:Id=\"\"><wsse:Username></wsse:Username><wsse:Password></wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference><wsa:Address>urn</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType></wst:RequestSecurityToken></s:Body></s:Envelope>",
			giveResp: defs.SAMLDefinitions{
				Body: defs.Body{
					RequestSecurityTokenResponseCollection: defs.RequestSecurityTokenResponseCollection{
						RequestSecurityTokenResponse: []defs.RequestSecurityTokenResponse{
							{
								RequestedSecurityToken: defs.RequestedSecurityToken{
									Assertion: defs.Assertion{
										Text: "hello",
										XMLName: xml.Name{
											Local: "Assertion",
										},
										Saml: samlv1Assertion,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc:              "Success: SAMLV1 assertion with AuthorizationTypeWindowsIntegratedAuth",
			endpoint:          defs.Endpoint{Version: defs.Trust13, URL: "upEndpoint"},
			action:            SoapActionDefault,
			authorizationType: authority.ATWindowsIntegrated,
			body:              "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><s:Header><wsa:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action><wsa:messageID>urn:uuid:fb8ec65b-f117-468f-b4e8-50c5e802affe</wsa:messageID><wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo><wsa:To s:mustUnderstand=\"1\">upEndpoint</wsa:To><wsse:Security s:mustUnderstand=\"\" xmlns:wsse=\"\"><wsu:Timestamp wsu:Id=\"\"><wsu:Created></wsu:Created><wsu:Expires></wsu:Expires></wsu:Timestamp><wsse:UsernameToken wsu:Id=\"\"><wsse:Username></wsse:Username><wsse:Password></wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference><wsa:Address>urn</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType></wst:RequestSecurityToken></s:Body></s:Envelope>",
			giveResp: defs.SAMLDefinitions{
				Body: defs.Body{
					RequestSecurityTokenResponseCollection: defs.RequestSecurityTokenResponseCollection{
						RequestSecurityTokenResponse: []defs.RequestSecurityTokenResponse{
							{
								RequestedSecurityToken: defs.RequestedSecurityToken{
									Assertion: defs.Assertion{
										Text: "hello",
										XMLName: xml.Name{
											Local: "Assertion",
										},
										Saml: samlv1Assertion,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			desc:              "Success: SAMLV2 assertion with AuthorizationTypeUsernamePassword",
			endpoint:          defs.Endpoint{Version: defs.Trust13, URL: "upEndpoint"},
			action:            SoapActionDefault,
			authorizationType: authority.ATUsernamePassword,
			body:              "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://www.w3.org/2005/08/addressing\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\"><s:Header><wsa:Action s:mustUnderstand=\"1\">http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue</wsa:Action><wsa:messageID>urn:uuid:fb8ec65b-f117-468f-b4e8-50c5e802affe</wsa:messageID><wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo><wsa:To s:mustUnderstand=\"1\">upEndpoint</wsa:To><wsse:Security s:mustUnderstand=\"\" xmlns:wsse=\"\"><wsu:Timestamp wsu:Id=\"\"><wsu:Created></wsu:Created><wsu:Expires></wsu:Expires></wsu:Timestamp><wsse:UsernameToken wsu:Id=\"\"><wsse:Username></wsse:Username><wsse:Password></wsse:Password></wsse:UsernameToken></wsse:Security></s:Header><s:Body><wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"><wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference><wsa:Address>urn</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer</wst:KeyType><wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType></wst:RequestSecurityToken></s:Body></s:Envelope>",
			giveResp: defs.SAMLDefinitions{
				Body: defs.Body{
					RequestSecurityTokenResponseCollection: defs.RequestSecurityTokenResponseCollection{
						RequestSecurityTokenResponse: []defs.RequestSecurityTokenResponse{
							{
								RequestedSecurityToken: defs.RequestedSecurityToken{
									Assertion: defs.Assertion{
										Text: "hello",
										XMLName: xml.Name{
											Local: "Assertion",
										},
										Saml: samlv2Assertion,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		fake := &fakeXMLCaller{err: test.commErr, giveResp: test.giveResp}
		client := Client{Comm: fake}

		authParams.AuthorizationType = test.authorizationType

		// We don't care about the result, that is just a translation from the XML handled
		// in the comm package via wstrust.CreateWsTrustMexDocumentFromDef().
		// We care only that the comm package got the right inputs.
		_, err := client.SAMLTokenInfo(context.Background(), authParams, "urn", test.endpoint)
		switch {
		case err == nil && test.err:
			t.Errorf("TestSAMLTokenInfo(%s): got err == nil , want err != nil", test.desc)
			continue
		case err != nil && !test.err:
			t.Errorf("TestSAMLTokenInfo(%s): got err == %s , want err == nil", test.desc, err)
			continue
		case err != nil:
			continue
		}

		if err := fake.compareSOAP(test.action, test.endpoint.URL, test.body, &defs.SAMLDefinitions{}); err != nil {
			t.Errorf("TestSAMLTokenInfo(%s): %s", test.desc, err)
		}
	}
}

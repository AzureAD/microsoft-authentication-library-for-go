// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	log "github.com/sirupsen/logrus"
)

type Response struct {
	responseData string
}

// TODO(jdoak): Delete this after integration of "ops" package.

func CreateWsTrustResponse(resp *http.Response) (Response, error) {
	response := Response{}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return response, err
	}
	response.responseData = string(body)
	return response, nil

	// todo: return error here
	// pugi::xml_parse_result result = _doc.load_string(response.c_str());
	// if (!result)
	// {
	// "Failed to parse SAML response '%s', response");
	// }

	// auto fault = _doc.child("s:Envelope").child("s:Body").child("s:Fault");
	// if (fault != nullptr)
	// {
	//         "SAML assertion indicates error: Code '%s' Subcode '%s' Reason '%s'",
	//         fault.child("s:Code").child_value("s:Value"),
	//         fault.child("s:Code").child("s:Subcode").child_value("s:Value"),
	//         fault.child("s:Reason").child_value("s:Text"));
	// }
}

func (wsTrustResponse *Response) GetSAMLAssertion(endpoint Endpoint) (SamlTokenInfo, error) {
	switch endpoint.EndpointVersion {
	case Trust2005:
		return SamlTokenInfo{}, errors.New("WS Trust 2005 support is not implemented")
	case Trust13:
		log.Trace("Extracting assertion from WS-Trust 1.3 token:")
		samldefinitions := &SAMLDefinitions{}
		var err = xml.Unmarshal([]byte(wsTrustResponse.responseData), samldefinitions)
		if err != nil {
			return SamlTokenInfo{}, err
		}

		for _, tokenResponse := range samldefinitions.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse {
			token := tokenResponse.RequestedSecurityToken
			if token.Assertion.XMLName.Local != "" {
				log.Trace("Found valid assertion")
				assertion := token.AssertionRawXML

				samlVersion := token.Assertion.Saml
				switch samlVersion {
				case "urn:oasis:names:tc:SAML:1.0:assertion":
					log.Trace("Retrieved WS-Trust 1.3 / SAML V1 assertion")
					return createSamlTokenInfo(msalbase.SAMLV1Grant, assertion), nil
				case "urn:oasis:names:tc:SAML:2.0:assertion":
					log.Trace("Retrieved WS-Trust 1.3 / SAML V2 assertion")
					return createSamlTokenInfo(msalbase.SAMLV2Grant, assertion), nil
				}
				return SamlTokenInfo{}, fmt.Errorf("Couldn't parse SAML assertion, version unknown: '%s'", samlVersion)
			}
		}
		return SamlTokenInfo{}, errors.New("couldn't find SAML assertion")
	}
	return SamlTokenInfo{}, errors.New("unknown WS-Trust version")
}

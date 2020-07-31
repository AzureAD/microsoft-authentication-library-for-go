// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import (
	"encoding/xml"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

type WsTrustResponse struct {
	responseData string
}

func CreateWsTrustResponse(responseData string) *WsTrustResponse {
	response := &WsTrustResponse{responseData}
	return response

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

func (wsTrustResponse *WsTrustResponse) GetSAMLAssertion(endpoint *WsTrustEndpoint) (*SamlTokenInfo, error) {
	switch endpoint.EndpointVersion {
	case Trust2005:
		return nil, errors.New("WS Trust 2005 support is not implemented")
	case Trust13:
		{
			log.Trace("Extracting assertion from WS-Trust 1.3 token:")

			samldefinitions := &samldefinitions{}
			var err = xml.Unmarshal([]byte(wsTrustResponse.responseData), samldefinitions)
			if err != nil {
				return nil, err
			}

			for _, tokenResponse := range samldefinitions.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse {
				token := tokenResponse.RequestedSecurityToken
				if token.Assertion.XMLName.Local != "" {
					log.Trace("Found valid assertion")
					assertion := token.AssertionRawXML

					samlVersion := token.Assertion.Saml
					if samlVersion == "urn:oasis:names:tc:SAML:1.0:assertion" {
						log.Trace("Retrieved WS-Trust 1.3 / SAML V1 assertion")
						return CreateSamlTokenInfo(SamlV1, assertion), nil
					}
					if samlVersion == "urn:oasis:names:tc:SAML:2.0:assertion" {
						log.Trace("Retrieved WS-Trust 1.3 / SAML V2 assertion")
						return CreateSamlTokenInfo(SamlV2, assertion), nil
					}

					return nil, fmt.Errorf("Couldn't parse SAML assertion, version unknown: '%s'", samlVersion)
				}
			}

			return nil, errors.New("couldn't find SAML assertion")
		}
	default:
		return nil, errors.New("unknown WS-Trust version")
	}
}

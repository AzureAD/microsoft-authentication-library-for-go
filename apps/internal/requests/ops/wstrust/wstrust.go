// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package wstrust provides a client for communicating with a WSTrust (https://en.wikipedia.org/wiki/WS-Trust#:~:text=WS%2DTrust%20is%20a%20WS,in%20a%20secure%20message%20exchange.)
for the purposes of extracting metadata from the service. This data can be used to acquire
tokens using the accesstokens.Client.GetAccessTokenFromSamlGrant() call.
*/
package wstrust

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/requests/ops/wstrust/internal/defs"
)

type xmlCaller interface {
	XMLCall(ctx context.Context, endpoint string, headers http.Header, qv url.Values, resp interface{}) error
	SOAPCall(ctx context.Context, endpoint, action string, headers http.Header, qv url.Values, body string, resp interface{}) error
}

type SamlTokenInfo struct {
	AssertionType string // Should be either constants SAMLV1Grant or SAMLV2Grant.
	Assertion     string
}

// Client represents the REST calls to get tokens from token generator backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm xmlCaller
}

// GetMex provides metadata about a wstrust service.
func (c Client) GetMex(ctx context.Context, federationMetadataURL string) (defs.MexDocument, error) {
	resp := defs.Definitions{}
	err := c.Comm.XMLCall(
		ctx,
		federationMetadataURL,
		http.Header{},
		nil,
		&resp,
	)
	if err != nil {
		return defs.MexDocument{}, err
	}

	return defs.CreateWsTrustMexDocumentFromDef(resp)
}

const (
	SoapActionDefault = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"

	// Note: Commented out because this action is not supported. It was in the original code
	// but only used in a switch where it errored. Since there was only one value, a default
	// worked better. However, buildTokenRequestMessage() had 2005 support.  I'm not actually
	// sure what's going on here. It like we have half support.  For now this is here just
	// for documentation purposes in case we are going to add support.
	//
	// SoapActionWSTrust2005 = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"
)

// GetSAMLTokenInfo provides SAML information that is used to generate a SAML token.
func (c Client) GetSAMLTokenInfo(ctx context.Context, authParameters msalbase.AuthParametersInternal, cloudAudienceURN string, endpoint defs.Endpoint) (SamlTokenInfo, error) {
	var wsTrustRequestMessage string
	var err error

	switch authParameters.AuthorizationType {
	case msalbase.AuthorizationTypeWindowsIntegratedAuth:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageWIA(cloudAudienceURN)
		if err != nil {
			return SamlTokenInfo{}, err
		}
	case msalbase.AuthorizationTypeUsernamePassword:
		wsTrustRequestMessage, err = endpoint.BuildTokenRequestMessageUsernamePassword(
			cloudAudienceURN, authParameters.Username, authParameters.Password)
		if err != nil {
			return SamlTokenInfo{}, err
		}
	default:
		return SamlTokenInfo{}, fmt.Errorf("unknown auth type %v", authParameters.AuthorizationType)
	}

	var soapAction string
	switch endpoint.EndpointVersion {
	case defs.Trust13:
		soapAction = SoapActionDefault
	case defs.Trust2005:
		return SamlTokenInfo{}, errors.New("WS Trust 2005 support is not implemented")
	default:
		return SamlTokenInfo{}, fmt.Errorf("the SOAP endpoint for a wstrust call had an invalid version: %v", endpoint.EndpointVersion)
	}

	resp := defs.SAMLDefinitions{}
	err = c.Comm.SOAPCall(ctx, endpoint.URL, soapAction, http.Header{}, nil, wsTrustRequestMessage, &resp)
	if err != nil {
		return SamlTokenInfo{}, err
	}

	return c.samlAssertion(resp)
}

const (
	samlv1Assertion = "urn:oasis:names:tc:SAML:1.0:assertion"
	samlv2Assertion = "urn:oasis:names:tc:SAML:2.0:assertion"
)

func (c Client) samlAssertion(def defs.SAMLDefinitions) (SamlTokenInfo, error) {
	for _, tokenResponse := range def.Body.RequestSecurityTokenResponseCollection.RequestSecurityTokenResponse {
		token := tokenResponse.RequestedSecurityToken
		if token.Assertion.XMLName.Local != "" {
			assertion := token.AssertionRawXML

			samlVersion := token.Assertion.Saml
			switch samlVersion {
			case samlv1Assertion:
				return SamlTokenInfo{AssertionType: msalbase.SAMLV1Grant, Assertion: assertion}, nil
			case samlv2Assertion:
				return SamlTokenInfo{AssertionType: msalbase.SAMLV2Grant, Assertion: assertion}, nil
			}
			return SamlTokenInfo{}, fmt.Errorf("couldn't parse SAML assertion, version unknown: %q", samlVersion)
		}
	}
	return SamlTokenInfo{}, errors.New("unknown WS-Trust version")
}
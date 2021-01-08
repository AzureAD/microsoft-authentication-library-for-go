// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package defs

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

//go:generate stringer -type=wsEndpointType

type wsEndpointType int

const (
	wsEndpointTypeUsernamePassword wsEndpointType = iota
	wsEndpointTypeWindowsTransport
)

type wsEndpointData struct {
	Version      EndpointVersion
	EndpointType wsEndpointType
}

const trust13Spec string = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
const trust2005Spec string = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"

type MexDocument struct {
	UsernamePasswordEndpoint Endpoint
	windowsTransportEndpoint Endpoint
	policies                 map[string]wsEndpointType
	bindings                 map[string]wsEndpointData
}

func updateEndpoint(cached *Endpoint, found Endpoint) bool {
	if cached == nil || cached.EndpointVersion == UnknownTrust {
		*cached = found
		return true
	}
	if (*cached).EndpointVersion == Trust2005 && found.EndpointVersion == Trust13 {
		*cached = found
		return true
	}
	return false
}

// TODO(jdoak): Refactor into smaller bits
// TODO(msal): Someone needs to write tests for this.

func NewFromHTTP(resp *http.Response) (MexDocument, error) {
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return MexDocument{}, err
	}
	definitions := Definitions{}
	err = xml.Unmarshal(body, &definitions)
	if err != nil {
		return MexDocument{}, err
	}
	return NewFromDef(definitions)
}

// NewFromDef creates a new MexDocument.
func NewFromDef(definitions Definitions) (MexDocument, error) {
	policies := make(map[string]wsEndpointType)

	for _, policy := range definitions.Policy {
		if policy.ExactlyOne.All.SignedEncryptedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			policies["#"+policy.ID] = wsEndpointTypeUsernamePassword
		}
		if policy.ExactlyOne.All.SignedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			policies["#"+policy.ID] = wsEndpointTypeUsernamePassword
		}
		if policy.ExactlyOne.All.NegotiateAuthentication.XMLName.Local != "" {
			policies["#"+policy.ID] = wsEndpointTypeWindowsTransport
		}
	}

	bindings := make(map[string]wsEndpointData)

	for _, binding := range definitions.Binding {
		policyName := binding.PolicyReference.URI
		transport := binding.Binding.Transport

		if transport == "http://schemas.xmlsoap.org/soap/http" {
			if policy, ok := policies[policyName]; ok {
				bindingName := binding.Name
				specVersion := binding.Operation.Operation.SoapAction

				if specVersion == trust13Spec {
					bindings[bindingName] = wsEndpointData{Trust13, policy}
				} else if specVersion == trust2005Spec {
					bindings[bindingName] = wsEndpointData{Trust2005, policy}
				} else {
					return MexDocument{}, errors.New("found unknown spec version in mex document")
				}
			}
		}
	}

	var (
		usernamePasswordEndpoint Endpoint
		windowsTransportEndpoint Endpoint
	)

	for _, port := range definitions.Service.Port {
		bindingName := port.Binding

		index := strings.Index(bindingName, ":")
		if index != -1 {
			bindingName = bindingName[index+1:]
		}

		if binding, ok := bindings[bindingName]; ok {
			url := strings.TrimSpace(port.EndpointReference.Address.Text)
			endpoint, err := createWsTrustEndpoint(binding.Version, url)
			if err != nil {
				return MexDocument{}, fmt.Errorf("cannot create MexDocument: %w", err)
			}

			switch binding.EndpointType {
			case wsEndpointTypeUsernamePassword:
				updateEndpoint(&usernamePasswordEndpoint, endpoint)
			case wsEndpointTypeWindowsTransport:
				updateEndpoint(&windowsTransportEndpoint, endpoint)
			default:
				return MexDocument{}, errors.New("found unknown port type in MEX document")
			}
		}
	}

	doc := MexDocument{usernamePasswordEndpoint, windowsTransportEndpoint, policies, bindings}
	return doc, nil
}

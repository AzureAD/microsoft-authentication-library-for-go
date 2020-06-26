// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import (
	"encoding/xml"
	"errors"
	"strings"

	log "github.com/sirupsen/logrus"
)

type WsEndpointType int

const (
	WsEndpointTypeUsernamePassword WsEndpointType = iota
	WsEndpointTypeWindowsTransport
)

type WsEndpointData struct {
	Version      WsTrustEndpointVersion
	EndpointType WsEndpointType
}

const trust13Spec string = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
const trust2005Spec string = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"

type WsTrustMexDocument struct {
	UsernamePasswordEndpoint WsTrustEndpoint
	windowsTransportEndpoint WsTrustEndpoint
	policies                 map[string]WsEndpointType
	bindings                 map[string]WsEndpointData
}

func updateEndpoint(cached *WsTrustEndpoint, found WsTrustEndpoint) bool {
	if cached == nil {
		log.Trace("No endpoint cached, using found endpoint")
		*cached = found
		return true
	}
	if (*cached).EndpointVersion == Trust2005 && found.EndpointVersion == Trust13 {
		log.Trace("Cached endpoint is v2005, replacing with v1.3")
		*cached = found
		return true
	}
	return false
}

func CreateWsTrustMexDocument(responseData string) (*WsTrustMexDocument, error) {
	definitions := &definitions{}
	var err = xml.Unmarshal([]byte(responseData), definitions)
	if err != nil {
		return nil, err
	}

	policies := make(map[string]WsEndpointType)

	for _, policy := range definitions.Policy {
		if policy.ExactlyOne.All.SignedEncryptedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			log.Trace("Found Policy with UsernamePassword 1.3: " + policy.ID)
			policies["#"+policy.ID] = WsEndpointTypeUsernamePassword
		}
		if policy.ExactlyOne.All.SignedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			log.Trace("Found Policy with UsernamePassword 2005: " + policy.ID)
			policies["#"+policy.ID] = WsEndpointTypeUsernamePassword
		}
		if policy.ExactlyOne.All.NegotiateAuthentication.XMLName.Local != "" {
			log.Trace("Found policy with WindowsTransport: " + policy.ID)
			policies["#"+policy.ID] = WsEndpointTypeWindowsTransport
		}
	}

	bindings := make(map[string]WsEndpointData)

	for _, binding := range definitions.Binding {
		policyName := binding.PolicyReference.URI
		log.Trace(policyName)
		transport := binding.Binding.Transport

		if transport == "http://schemas.xmlsoap.org/soap/http" {
			if policy, ok := policies[policyName]; ok {
				bindingName := binding.Name
				specVersion := binding.Operation.Operation.SoapAction
				log.Tracef("Found binding %v Spec %v", bindingName, specVersion)

				if specVersion == trust13Spec {
					bindings[bindingName] = WsEndpointData{Trust13, policy}
				} else if specVersion == trust2005Spec {
					bindings[bindingName] = WsEndpointData{Trust2005, policy}
				} else {
					return nil, errors.New("Found unknown spec version in mex document")
				}
			}
		}
	}

	var usernamePasswordEndpoint WsTrustEndpoint
	var windowsTransportEndpoint WsTrustEndpoint

	for _, port := range definitions.Service.Port {
		bindingName := port.Binding
		log.Trace("Parsing port with binding name: " + bindingName)

		index := strings.Index(bindingName, ":")
		if index != -1 {
			bindingName = bindingName[index+1 : len(bindingName)]
		}

		if binding, ok := bindings[bindingName]; ok {
			url := port.EndpointReference.Address.Text
			url = strings.Trim(url, " ")

			endpoint := CreateWsTrustEndpoint(binding.Version, url)

			log.Tracef("Associated port '%v' with binding, url '%v'", bindingName, url)
			switch binding.EndpointType {
			case WsEndpointTypeUsernamePassword:
				if updateEndpoint(&usernamePasswordEndpoint, endpoint) {
					log.Tracef("Updated cached username/password endpoint to binding '%v'", bindingName)
				}
				break
			case WsEndpointTypeWindowsTransport:
				if updateEndpoint(&windowsTransportEndpoint, endpoint) {
					log.Tracef("Updated cached windows transport endpoint to binding '%v'", bindingName)
				}
				break
			default:
				return nil, errors.New("Found unknown port type in MEX document")
			}
		}
	}

	doc := &WsTrustMexDocument{usernamePasswordEndpoint, windowsTransportEndpoint, policies, bindings}
	log.Trace("Created WsTrustMexDocument!")
	return doc, nil
}

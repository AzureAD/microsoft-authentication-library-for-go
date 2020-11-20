// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import (
	"encoding/xml"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

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

// TODO(jdoak): Refactor into smaller bits

func CreateWsTrustMexDocument(resp *http.Response) (MexDocument, error) {
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return MexDocument{}, err
	}
	definitions := &definitions{}
	err = xml.Unmarshal(body, definitions)
	if err != nil {
		return MexDocument{}, err
	}

	policies := make(map[string]wsEndpointType)

	for _, policy := range definitions.Policy {
		if policy.ExactlyOne.All.SignedEncryptedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			log.Trace("Found Policy with UsernamePassword 1.3: " + policy.ID)
			policies["#"+policy.ID] = wsEndpointTypeUsernamePassword
		}
		if policy.ExactlyOne.All.SignedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			log.Trace("Found Policy with UsernamePassword 2005: " + policy.ID)
			policies["#"+policy.ID] = wsEndpointTypeUsernamePassword
		}
		if policy.ExactlyOne.All.NegotiateAuthentication.XMLName.Local != "" {
			log.Trace("Found policy with WindowsTransport: " + policy.ID)
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
				log.Tracef("Found binding %v Spec %v", bindingName, specVersion)

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

	var usernamePasswordEndpoint Endpoint
	var windowsTransportEndpoint Endpoint

	for _, port := range definitions.Service.Port {
		bindingName := port.Binding
		log.Trace("Parsing port with binding name: " + bindingName)

		index := strings.Index(bindingName, ":")
		if index != -1 {
			bindingName = bindingName[index+1:]
		}

		if binding, ok := bindings[bindingName]; ok {
			url := port.EndpointReference.Address.Text
			url = strings.Trim(url, " ")

			endpoint := createWsTrustEndpoint(binding.Version, url)

			log.Tracef("Associated port '%v' with binding, url '%v'", bindingName, url)
			switch binding.EndpointType {
			case wsEndpointTypeUsernamePassword:
				if updateEndpoint(&usernamePasswordEndpoint, endpoint) {
					log.Tracef("Updated cached username/password endpoint to binding '%v'", bindingName)
				}
				break
			case wsEndpointTypeWindowsTransport:
				if updateEndpoint(&windowsTransportEndpoint, endpoint) {
					log.Tracef("Updated cached windows transport endpoint to binding '%v'", bindingName)
				}
				break
			default:
				return MexDocument{}, errors.New("found unknown port type in MEX document")
			}
		}
	}

	doc := MexDocument{usernamePasswordEndpoint, windowsTransportEndpoint, policies, bindings}
	log.Trace("Created WsTrustMexDocument!")
	return doc, nil
}

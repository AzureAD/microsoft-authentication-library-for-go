// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package defs

import (
	"errors"
	"fmt"
	"log"
	"strings"
)

//go:generate stringer -type=endpointType

type endpointType int

const (
	etUnknown endpointType = iota
	etUsernamePassword
	etWindowsTransport
)

type wsEndpointData struct {
	Version      Version
	EndpointType endpointType
}

const trust13Spec string = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"
const trust2005Spec string = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue"

type MexDocument struct {
	UsernamePasswordEndpoint Endpoint
	WindowsTransportEndpoint Endpoint
	policies                 map[string]endpointType
	bindings                 map[string]wsEndpointData
}

func updateEndpoint(cached *Endpoint, found Endpoint) {
	if cached == nil || cached.Version == TrustUnknown {
		log.Println("\twas set")
		*cached = found
		return
	}
	if (*cached).Version == Trust2005 && found.Version == Trust13 {
		log.Println("\twas set")
		*cached = found
		return
	}
	log.Println("\twas not set")
}

// TODO(msal): Someone needs to write tests for everything below.

// NewFromDef creates a new MexDocument.
func NewFromDef(defs Definitions) (MexDocument, error) {
	policies, err := policies(defs)
	if err != nil {
		return MexDocument{}, err
	}

	bindings, err := bindings(defs, policies)
	if err != nil {
		return MexDocument{}, err
	}

	userPass, windows, err := endpoints(defs, bindings)
	if err != nil {
		return MexDocument{}, err
	}

	log.Println("userPass endpoint: ", userPass.URL)
	return MexDocument{
		UsernamePasswordEndpoint: userPass,
		WindowsTransportEndpoint: windows,
		policies:                 policies,
		bindings:                 bindings,
	}, nil
}

func policies(defs Definitions) (map[string]endpointType, error) {
	policies := make(map[string]endpointType, len(defs.Policy))

	for _, policy := range defs.Policy {
		if policy.ExactlyOne.All.NegotiateAuthentication.XMLName.Local != "" {
			if policy.ExactlyOne.All.TransportBinding.Sp != "" && policy.ID != "" {
				policies["#"+policy.ID] = etWindowsTransport
			}
		}

		if policy.ExactlyOne.All.SignedEncryptedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			if policy.ExactlyOne.All.TransportBinding.Sp != "" && policy.ID != "" {
				policies["#"+policy.ID] = etUsernamePassword
			}
		}
		if policy.ExactlyOne.All.SignedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			if policy.ExactlyOne.All.TransportBinding.Sp != "" && policy.ID != "" {
				policies["#"+policy.ID] = etUsernamePassword
			}
		}
	}

	if len(policies) == 0 {
		return policies, errors.New("no policies for mex document")
	}

	return policies, nil
}

func bindings(defs Definitions, policies map[string]endpointType) (map[string]wsEndpointData, error) {
	bindings := make(map[string]wsEndpointData, len(defs.Binding))

	for _, binding := range defs.Binding {
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
					return nil, errors.New("found unknown spec version in mex document")
				}
			}
		}
	}
	return bindings, nil
}

func endpoints(defs Definitions, bindings map[string]wsEndpointData) (userPass, windows Endpoint, err error) {
	log.Println("RUN")
	for _, port := range defs.Service.Port {
		bindingName := port.Binding

		index := strings.Index(bindingName, ":")
		if index != -1 {
			bindingName = bindingName[index+1:]
		}

		if binding, ok := bindings[bindingName]; ok {
			url := strings.TrimSpace(port.EndpointReference.Address.Text)
			log.Printf("version(%s) url(%s): ", binding.Version, url)
			if url == "" {
				return Endpoint{}, Endpoint{}, fmt.Errorf("MexDocument cannot have blank URL endpoint")
			}
			if binding.Version == TrustUnknown {
				return Endpoint{}, Endpoint{}, fmt.Errorf("endpoint version unknown")
			}
			endpoint := Endpoint{Version: binding.Version, URL: url}

			switch binding.EndpointType {
			case etUsernamePassword:
				log.Println("update userpass")
				updateEndpoint(&userPass, endpoint)
			case etWindowsTransport:
				log.Println("update windows")
				updateEndpoint(&windows, endpoint)
			default:
				return Endpoint{}, Endpoint{}, errors.New("found unknown port type in MEX document")
			}
		}
	}
	return userPass, windows, nil
}

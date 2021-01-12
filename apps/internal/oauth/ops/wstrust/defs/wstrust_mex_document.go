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
		// TODO(msal): These if statements are a little weird to me. For any single policy
		// we determine a type, which is fine. But after we determine the type, we don't move
		// on to the next policy (via a continue). This means that we are going to check that
		// next value and possibly override what we already found. If that is what we are doing
		// we should document that logic here. If not, we should add continue to the inner
		// if statements after the EndpointType assignment.
		if policy.ExactlyOne.All.SignedEncryptedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			if policy.ExactlyOne.All.TransportBinding.Sp != "" {
				policies["#"+policy.ID] = etUsernamePassword
			}
		}
		if policy.ExactlyOne.All.SignedSupportingTokens.Policy.UsernameToken.Policy.WssUsernameToken10.XMLName.Local != "" {
			if policy.ExactlyOne.All.TransportBinding.Sp != "" {
				policies["#"+policy.ID] = etUsernamePassword
			}
		}
		if policy.ExactlyOne.All.NegotiateAuthentication.XMLName.Local != "" {
			policies["#"+policy.ID] = etWindowsTransport
		}

		// TODO(msal): I (jdoak) added this etUnknown value and this sanity check. The old way
		// was this would default to etUsernamePassword because it was the zero value. This
		// is a bad practice to do via "fallthrough" instead of explicitly. If this is incorrect
		// to fail, then this should be changed to explicitly set etUsernamePassword when
		// not found.
		/*
			if policies["#"+policy.ID] == etUnknown {
				return nil, fmt.Errorf("for MexDocument policy(%d), we could not discern a endpoint type", i)
			}
		*/
		policies["#"+policy.ID] = etUsernamePassword
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

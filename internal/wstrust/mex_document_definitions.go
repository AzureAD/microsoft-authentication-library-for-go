// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import "encoding/xml"

type definitions struct {
	XMLName         xml.Name `xml:"definitions"`
	Text            string   `xml:",chardata"`
	Name            string   `xml:"name,attr"`
	TargetNamespace string   `xml:"targetNamespace,attr"`
	Wsdl            string   `xml:"wsdl,attr"`
	Xsd             string   `xml:"xsd,attr"`
	T               string   `xml:"t,attr"`
	Soapenc         string   `xml:"soapenc,attr"`
	Soap            string   `xml:"soap,attr"`
	Tns             string   `xml:"tns,attr"`
	Msc             string   `xml:"msc,attr"`
	Wsam            string   `xml:"wsam,attr"`
	Soap12          string   `xml:"soap12,attr"`
	Wsa10           string   `xml:"wsa10,attr"`
	Wsa             string   `xml:"wsa,attr"`
	Wsaw            string   `xml:"wsaw,attr"`
	Wsx             string   `xml:"wsx,attr"`
	Wsap            string   `xml:"wsap,attr"`
	Wsu             string   `xml:"wsu,attr"`
	Trust           string   `xml:"trust,attr"`
	Wsp             string   `xml:"wsp,attr"`
	Policy          []struct {
		Text       string `xml:",chardata"`
		ID         string `xml:"Id,attr"`
		ExactlyOne struct {
			Text string `xml:",chardata"`
			All  struct {
				Text                    string `xml:",chardata"`
				NegotiateAuthentication struct {
					Text    string `xml:",chardata"`
					HTTP    string `xml:"http,attr"`
					XMLName xml.Name
				} `xml:"NegotiateAuthentication"`
				TransportBinding struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text           string `xml:",chardata"`
						TransportToken struct {
							Text   string `xml:",chardata"`
							Policy struct {
								Text       string `xml:",chardata"`
								HTTPSToken struct {
									Text                     string `xml:",chardata"`
									RequireClientCertificate string `xml:"RequireClientCertificate,attr"`
								} `xml:"HttpsToken"`
							} `xml:"Policy"`
						} `xml:"TransportToken"`
						AlgorithmSuite struct {
							Text   string `xml:",chardata"`
							Policy struct {
								Text     string `xml:",chardata"`
								Basic256 struct {
									Text string `xml:",chardata"`
								} `xml:"Basic256"`
								Basic128 struct {
									Text string `xml:",chardata"`
								} `xml:"Basic128"`
							} `xml:"Policy"`
						} `xml:"AlgorithmSuite"`
						Layout struct {
							Text   string `xml:",chardata"`
							Policy struct {
								Text   string `xml:",chardata"`
								Strict struct {
									Text string `xml:",chardata"`
								} `xml:"Strict"`
							} `xml:"Policy"`
						} `xml:"Layout"`
						IncludeTimestamp struct {
							Text string `xml:",chardata"`
						} `xml:"IncludeTimestamp"`
					} `xml:"Policy"`
				} `xml:"TransportBinding"`
				UsingAddressing struct {
					Text string `xml:",chardata"`
				} `xml:"UsingAddressing"`
				EndorsingSupportingTokens struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text      string `xml:",chardata"`
						X509Token struct {
							Text         string `xml:",chardata"`
							IncludeToken string `xml:"IncludeToken,attr"`
							Policy       struct {
								Text                       string `xml:",chardata"`
								RequireThumbprintReference struct {
									Text string `xml:",chardata"`
								} `xml:"RequireThumbprintReference"`
								WssX509V3Token10 struct {
									Text string `xml:",chardata"`
								} `xml:"WssX509V3Token10"`
							} `xml:"Policy"`
						} `xml:"X509Token"`
						RsaToken struct {
							Text         string `xml:",chardata"`
							IncludeToken string `xml:"IncludeToken,attr"`
							Optional     string `xml:"Optional,attr"`
							Mssp         string `xml:"mssp,attr"`
						} `xml:"RsaToken"`
						SignedParts struct {
							Text   string `xml:",chardata"`
							Header struct {
								Text      string `xml:",chardata"`
								Name      string `xml:"Name,attr"`
								Namespace string `xml:"Namespace,attr"`
							} `xml:"Header"`
						} `xml:"SignedParts"`
						KerberosToken struct {
							Text         string `xml:",chardata"`
							IncludeToken string `xml:"IncludeToken,attr"`
							Policy       struct {
								Text                         string `xml:",chardata"`
								WssGssKerberosV5ApReqToken11 struct {
									Text string `xml:",chardata"`
								} `xml:"WssGssKerberosV5ApReqToken11"`
							} `xml:"Policy"`
						} `xml:"KerberosToken"`
						IssuedToken struct {
							Text                         string `xml:",chardata"`
							IncludeToken                 string `xml:"IncludeToken,attr"`
							RequestSecurityTokenTemplate struct {
								Text    string `xml:",chardata"`
								KeyType struct {
									Text string `xml:",chardata"`
								} `xml:"KeyType"`
								EncryptWith struct {
									Text string `xml:",chardata"`
								} `xml:"EncryptWith"`
								SignatureAlgorithm struct {
									Text string `xml:",chardata"`
								} `xml:"SignatureAlgorithm"`
								CanonicalizationAlgorithm struct {
									Text string `xml:",chardata"`
								} `xml:"CanonicalizationAlgorithm"`
								EncryptionAlgorithm struct {
									Text string `xml:",chardata"`
								} `xml:"EncryptionAlgorithm"`
								KeySize struct {
									Text string `xml:",chardata"`
								} `xml:"KeySize"`
								KeyWrapAlgorithm struct {
									Text string `xml:",chardata"`
								} `xml:"KeyWrapAlgorithm"`
							} `xml:"RequestSecurityTokenTemplate"`
							Policy struct {
								Text                     string `xml:",chardata"`
								RequireInternalReference struct {
									Text string `xml:",chardata"`
								} `xml:"RequireInternalReference"`
							} `xml:"Policy"`
						} `xml:"IssuedToken"`
						KeyValueToken struct {
							Text         string `xml:",chardata"`
							IncludeToken string `xml:"IncludeToken,attr"`
							Optional     string `xml:"Optional,attr"`
						} `xml:"KeyValueToken"`
					} `xml:"Policy"`
				} `xml:"EndorsingSupportingTokens"`
				Wss11 struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text                     string `xml:",chardata"`
						MustSupportRefThumbprint struct {
							Text string `xml:",chardata"`
						} `xml:"MustSupportRefThumbprint"`
					} `xml:"Policy"`
				} `xml:"Wss11"`
				Trust10 struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text                    string `xml:",chardata"`
						MustSupportIssuedTokens struct {
							Text string `xml:",chardata"`
						} `xml:"MustSupportIssuedTokens"`
						RequireClientEntropy struct {
							Text string `xml:",chardata"`
						} `xml:"RequireClientEntropy"`
						RequireServerEntropy struct {
							Text string `xml:",chardata"`
						} `xml:"RequireServerEntropy"`
					} `xml:"Policy"`
				} `xml:"Trust10"`
				SignedSupportingTokens struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text          string `xml:",chardata"`
						UsernameToken struct {
							Text         string `xml:",chardata"`
							IncludeToken string `xml:"IncludeToken,attr"`
							Policy       struct {
								Text               string `xml:",chardata"`
								WssUsernameToken10 struct {
									Text    string `xml:",chardata"`
									XMLName xml.Name
								} `xml:"WssUsernameToken10"`
							} `xml:"Policy"`
						} `xml:"UsernameToken"`
					} `xml:"Policy"`
				} `xml:"SignedSupportingTokens"`
				Trust13 struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text                    string `xml:",chardata"`
						MustSupportIssuedTokens struct {
							Text string `xml:",chardata"`
						} `xml:"MustSupportIssuedTokens"`
						RequireClientEntropy struct {
							Text string `xml:",chardata"`
						} `xml:"RequireClientEntropy"`
						RequireServerEntropy struct {
							Text string `xml:",chardata"`
						} `xml:"RequireServerEntropy"`
					} `xml:"Policy"`
				} `xml:"Trust13"`
				SignedEncryptedSupportingTokens struct {
					Text   string `xml:",chardata"`
					Sp     string `xml:"sp,attr"`
					Policy struct {
						Text          string `xml:",chardata"`
						UsernameToken struct {
							Text         string `xml:",chardata"`
							IncludeToken string `xml:"IncludeToken,attr"`
							Policy       struct {
								Text               string `xml:",chardata"`
								WssUsernameToken10 struct {
									Text    string `xml:",chardata"`
									XMLName xml.Name
								} `xml:"WssUsernameToken10"`
							} `xml:"Policy"`
						} `xml:"UsernameToken"`
					} `xml:"Policy"`
				} `xml:"SignedEncryptedSupportingTokens"`
			} `xml:"All"`
		} `xml:"ExactlyOne"`
	} `xml:"Policy"`
	Types struct {
		Text   string `xml:",chardata"`
		Schema struct {
			Text            string `xml:",chardata"`
			TargetNamespace string `xml:"targetNamespace,attr"`
			Import          []struct {
				Text           string `xml:",chardata"`
				SchemaLocation string `xml:"schemaLocation,attr"`
				Namespace      string `xml:"namespace,attr"`
			} `xml:"import"`
		} `xml:"schema"`
	} `xml:"types"`
	Message []struct {
		Text string `xml:",chardata"`
		Name string `xml:"name,attr"`
		Part struct {
			Text    string `xml:",chardata"`
			Name    string `xml:"name,attr"`
			Element string `xml:"element,attr"`
		} `xml:"part"`
	} `xml:"message"`
	PortType []struct {
		Text      string `xml:",chardata"`
		Name      string `xml:"name,attr"`
		Operation struct {
			Text  string `xml:",chardata"`
			Name  string `xml:"name,attr"`
			Input struct {
				Text    string `xml:",chardata"`
				Action  string `xml:"Action,attr"`
				Message string `xml:"message,attr"`
			} `xml:"input"`
			Output struct {
				Text    string `xml:",chardata"`
				Action  string `xml:"Action,attr"`
				Message string `xml:"message,attr"`
			} `xml:"output"`
		} `xml:"operation"`
	} `xml:"portType"`
	Binding []struct {
		Text            string `xml:",chardata"`
		Name            string `xml:"name,attr"`
		Type            string `xml:"type,attr"`
		PolicyReference struct {
			Text string `xml:",chardata"`
			URI  string `xml:"URI,attr"`
		} `xml:"PolicyReference"`
		Binding struct {
			Text      string `xml:",chardata"`
			Transport string `xml:"transport,attr"`
		} `xml:"binding"`
		Operation struct {
			Text      string `xml:",chardata"`
			Name      string `xml:"name,attr"`
			Operation struct {
				Text       string `xml:",chardata"`
				SoapAction string `xml:"soapAction,attr"`
				Style      string `xml:"style,attr"`
			} `xml:"operation"`
			Input struct {
				Text string `xml:",chardata"`
				Body struct {
					Text string `xml:",chardata"`
					Use  string `xml:"use,attr"`
				} `xml:"body"`
			} `xml:"input"`
			Output struct {
				Text string `xml:",chardata"`
				Body struct {
					Text string `xml:",chardata"`
					Use  string `xml:"use,attr"`
				} `xml:"body"`
			} `xml:"output"`
		} `xml:"operation"`
	} `xml:"binding"`
	Service struct {
		Text string `xml:",chardata"`
		Name string `xml:"name,attr"`
		Port []struct {
			Text    string `xml:",chardata"`
			Name    string `xml:"name,attr"`
			Binding string `xml:"binding,attr"`
			Address struct {
				Text     string `xml:",chardata"`
				Location string `xml:"location,attr"`
			} `xml:"address"`
			EndpointReference struct {
				Text    string `xml:",chardata"`
				Address struct {
					Text string `xml:",chardata"`
				} `xml:"Address"`
				Identity struct {
					Text  string `xml:",chardata"`
					Xmlns string `xml:"xmlns,attr"`
					Spn   struct {
						Text string `xml:",chardata"`
					} `xml:"Spn"`
				} `xml:"Identity"`
			} `xml:"EndpointReference"`
		} `xml:"port"`
	} `xml:"service"`
}

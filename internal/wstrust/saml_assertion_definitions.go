// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import "encoding/xml"

type samldefinitions struct {
	XMLName xml.Name `xml:"Envelope"`
	Text    string   `xml:",chardata"`
	S       string   `xml:"s,attr"`
	A       string   `xml:"a,attr"`
	U       string   `xml:"u,attr"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
		} `xml:"Action"`
		Security struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"mustUnderstand,attr"`
			O              string `xml:"o,attr"`
			Timestamp      struct {
				Text    string `xml:",chardata"`
				ID      string `xml:"Id,attr"`
				Created struct {
					Text string `xml:",chardata"`
				} `xml:"Created"`
				Expires struct {
					Text string `xml:",chardata"`
				} `xml:"Expires"`
			} `xml:"Timestamp"`
		} `xml:"Security"`
	} `xml:"Header"`
	Body struct {
		Text                                   string `xml:",chardata"`
		RequestSecurityTokenResponseCollection struct {
			Text                         string `xml:",chardata"`
			Trust                        string `xml:"trust,attr"`
			RequestSecurityTokenResponse []struct {
				Text     string `xml:",chardata"`
				Lifetime struct {
					Text    string `xml:",chardata"`
					Created struct {
						Text string `xml:",chardata"`
						Wsu  string `xml:"wsu,attr"`
					} `xml:"Created"`
					Expires struct {
						Text string `xml:",chardata"`
						Wsu  string `xml:"wsu,attr"`
					} `xml:"Expires"`
				} `xml:"Lifetime"`
				AppliesTo struct {
					Text              string `xml:",chardata"`
					Wsp               string `xml:"wsp,attr"`
					EndpointReference struct {
						Text    string `xml:",chardata"`
						Wsa     string `xml:"wsa,attr"`
						Address struct {
							Text string `xml:",chardata"`
						} `xml:"Address"`
					} `xml:"EndpointReference"`
				} `xml:"AppliesTo"`
				RequestedSecurityToken struct {
					Text            string `xml:",chardata"`
					AssertionRawXML string `xml:",innerxml"`
					Assertion       struct {
						XMLName      xml.Name
						Text         string `xml:",chardata"`
						MajorVersion string `xml:"MajorVersion,attr"`
						MinorVersion string `xml:"MinorVersion,attr"`
						AssertionID  string `xml:"AssertionID,attr"`
						Issuer       string `xml:"Issuer,attr"`
						IssueInstant string `xml:"IssueInstant,attr"`
						Saml         string `xml:"saml,attr"`
						Conditions   struct {
							Text                         string `xml:",chardata"`
							NotBefore                    string `xml:"NotBefore,attr"`
							NotOnOrAfter                 string `xml:"NotOnOrAfter,attr"`
							AudienceRestrictionCondition struct {
								Text     string `xml:",chardata"`
								Audience struct {
									Text string `xml:",chardata"`
								} `xml:"Audience"`
							} `xml:"AudienceRestrictionCondition"`
						} `xml:"Conditions"`
						AttributeStatement struct {
							Text    string `xml:",chardata"`
							Subject struct {
								Text           string `xml:",chardata"`
								NameIdentifier struct {
									Text   string `xml:",chardata"`
									Format string `xml:"Format,attr"`
								} `xml:"NameIdentifier"`
								SubjectConfirmation struct {
									Text               string `xml:",chardata"`
									ConfirmationMethod struct {
										Text string `xml:",chardata"`
									} `xml:"ConfirmationMethod"`
								} `xml:"SubjectConfirmation"`
							} `xml:"Subject"`
							Attribute []struct {
								Text               string `xml:",chardata"`
								AttributeName      string `xml:"AttributeName,attr"`
								AttributeNamespace string `xml:"AttributeNamespace,attr"`
								AttributeValue     struct {
									Text string `xml:",chardata"`
								} `xml:"AttributeValue"`
							} `xml:"Attribute"`
						} `xml:"AttributeStatement"`
						AuthenticationStatement struct {
							Text                  string `xml:",chardata"`
							AuthenticationMethod  string `xml:"AuthenticationMethod,attr"`
							AuthenticationInstant string `xml:"AuthenticationInstant,attr"`
							Subject               struct {
								Text           string `xml:",chardata"`
								NameIdentifier struct {
									Text   string `xml:",chardata"`
									Format string `xml:"Format,attr"`
								} `xml:"NameIdentifier"`
								SubjectConfirmation struct {
									Text               string `xml:",chardata"`
									ConfirmationMethod struct {
										Text string `xml:",chardata"`
									} `xml:"ConfirmationMethod"`
								} `xml:"SubjectConfirmation"`
							} `xml:"Subject"`
						} `xml:"AuthenticationStatement"`
						Signature struct {
							Text       string `xml:",chardata"`
							Ds         string `xml:"ds,attr"`
							SignedInfo struct {
								Text                   string `xml:",chardata"`
								CanonicalizationMethod struct {
									Text      string `xml:",chardata"`
									Algorithm string `xml:"Algorithm,attr"`
								} `xml:"CanonicalizationMethod"`
								SignatureMethod struct {
									Text      string `xml:",chardata"`
									Algorithm string `xml:"Algorithm,attr"`
								} `xml:"SignatureMethod"`
								Reference struct {
									Text       string `xml:",chardata"`
									URI        string `xml:"URI,attr"`
									Transforms struct {
										Text      string `xml:",chardata"`
										Transform []struct {
											Text      string `xml:",chardata"`
											Algorithm string `xml:"Algorithm,attr"`
										} `xml:"Transform"`
									} `xml:"Transforms"`
									DigestMethod struct {
										Text      string `xml:",chardata"`
										Algorithm string `xml:"Algorithm,attr"`
									} `xml:"DigestMethod"`
									DigestValue struct {
										Text string `xml:",chardata"`
									} `xml:"DigestValue"`
								} `xml:"Reference"`
							} `xml:"SignedInfo"`
							SignatureValue struct {
								Text string `xml:",chardata"`
							} `xml:"SignatureValue"`
							KeyInfo struct {
								Text     string `xml:",chardata"`
								Xmlns    string `xml:"xmlns,attr"`
								X509Data struct {
									Text            string `xml:",chardata"`
									X509Certificate struct {
										Text string `xml:",chardata"`
									} `xml:"X509Certificate"`
								} `xml:"X509Data"`
							} `xml:"KeyInfo"`
						} `xml:"Signature"`
					} `xml:"Assertion"`
				} `xml:"RequestedSecurityToken"`
				RequestedAttachedReference struct {
					Text                   string `xml:",chardata"`
					SecurityTokenReference struct {
						Text          string `xml:",chardata"`
						TokenType     string `xml:"TokenType,attr"`
						O             string `xml:"o,attr"`
						K             string `xml:"k,attr"`
						KeyIdentifier struct {
							Text      string `xml:",chardata"`
							ValueType string `xml:"ValueType,attr"`
						} `xml:"KeyIdentifier"`
					} `xml:"SecurityTokenReference"`
				} `xml:"RequestedAttachedReference"`
				RequestedUnattachedReference struct {
					Text                   string `xml:",chardata"`
					SecurityTokenReference struct {
						Text          string `xml:",chardata"`
						TokenType     string `xml:"TokenType,attr"`
						O             string `xml:"o,attr"`
						K             string `xml:"k,attr"`
						KeyIdentifier struct {
							Text      string `xml:",chardata"`
							ValueType string `xml:"ValueType,attr"`
						} `xml:"KeyIdentifier"`
					} `xml:"SecurityTokenReference"`
				} `xml:"RequestedUnattachedReference"`
				TokenType struct {
					Text string `xml:",chardata"`
				} `xml:"TokenType"`
				RequestType struct {
					Text string `xml:",chardata"`
				} `xml:"RequestType"`
				KeyType struct {
					Text string `xml:",chardata"`
				} `xml:"KeyType"`
			} `xml:"RequestSecurityTokenResponse"`
		} `xml:"RequestSecurityTokenResponseCollection"`
	} `xml:"Body"`
}

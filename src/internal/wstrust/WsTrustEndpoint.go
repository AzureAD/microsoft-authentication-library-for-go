// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package wstrust

import (
	"encoding/xml"
	"time"

	log "github.com/sirupsen/logrus"

	// "github.com/AzureAD/microsoft-authentication-library-for-go/src/internal/msalbase"
	"internal/msalbase"
	uuid "github.com/twinj/uuid"
)

type WsTrustEndpointVersion int

const (
	Trust2005 WsTrustEndpointVersion = iota
	Trust13
)

type WsTrustEndpoint struct {
	endpointVersion WsTrustEndpointVersion
	url             string
}

func CreateWsTrustEndpoint(endpointVersion WsTrustEndpointVersion, url string) WsTrustEndpoint {
	return WsTrustEndpoint{endpointVersion, url}
}

func (wte *WsTrustEndpoint) GetVersion() WsTrustEndpointVersion {
	return wte.endpointVersion
}

type wsTrustTokenRequestEnvelope struct {
	XMLName xml.Name `xml:"s:Envelope"`
	Text    string   `xml:",chardata"`
	S       string   `xml:"xmlns:s,attr"`
	Wsa     string   `xml:"xmlns:wsa,attr"`
	Wsu     string   `xml:"xmlns:wsu,attr"`
	Header  struct {
		Text   string `xml:",chardata"`
		Action struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"s:mustUnderstand,attr"`
		} `xml:"wsa:Action"`
		MessageID struct {
			Text string `xml:",chardata"`
		} `xml:"wsa:messageID"`
		ReplyTo struct {
			Text    string `xml:",chardata"`
			Address struct {
				Text string `xml:",chardata"`
			} `xml:"wsa:Address"`
		} `xml:"wsa:ReplyTo"`
		To struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"s:mustUnderstand,attr"`
		} `xml:"wsa:To"`
		Security struct {
			Text           string `xml:",chardata"`
			MustUnderstand string `xml:"s:mustUnderstand,attr"`
			Wsse           string `xml:"xmlns:wsse,attr"`
			Timestamp      struct {
				Text    string `xml:",chardata"`
				ID      string `xml:"wsu:Id,attr"`
				Created struct {
					Text string `xml:",chardata"`
				} `xml:"wsu:Created"`
				Expires struct {
					Text string `xml:",chardata"`
				} `xml:"wsu:Expires"`
			} `xml:"wsu:Timestamp"`
			UsernameToken struct {
				Text     string `xml:",chardata"`
				ID       string `xml:"wsu:Id,attr"`
				Username struct {
					Text string `xml:",chardata"`
				} `xml:"wsse:Username"`
				Password struct {
					Text string `xml:",chardata"`
				} `xml:"wsse:Password"`
			} `xml:"wsse:UsernameToken"`
		} `xml:"wsse:Security"`
	} `xml:"s:Header"`
	Body struct {
		Text                 string `xml:",chardata"`
		RequestSecurityToken struct {
			Text      string `xml:",chardata"`
			Wst       string `xml:"xmlns:wst,attr"`
			AppliesTo struct {
				Text              string `xml:",chardata"`
				Wsp               string `xml:"xmlns:wsp,attr"`
				EndpointReference struct {
					Text    string `xml:",chardata"`
					Address struct {
						Text string `xml:",chardata"`
					} `xml:"wsa:Address"`
				} `xml:"wsa:EndpointReference"`
			} `xml:"wsp:AppliesTo"`
			KeyType struct {
				Text string `xml:",chardata"`
			} `xml:"wst:KeyType"`
			RequestType struct {
				Text string `xml:",chardata"`
			} `xml:"wst:RequestType"`
		} `xml:"wst:RequestSecurityToken"`
	} `xml:"s:Body"`
}

func buildTimeString(t time.Time) string {
	// Golang time formats are weird: https://stackoverflow.com/questions/20234104/how-to-format-current-time-using-a-yyyymmddhhmmss-format
	return t.Format("2006-01-02T15:04:05.000Z")
}

func (wte *WsTrustEndpoint) buildTokenRequestMessage(authType msalbase.AuthorizationType, cloudAudienceURN string, username string, password string) (string, error) {
	var soapAction string
	var trustNamespace string
	var keyType string
	var requestType string

	createdTime := time.Now().UTC()
	expiresTime := createdTime.Add(10 * time.Minute)

	if wte.endpointVersion == Trust2005 {
		log.Trace("Building WS-Trust token request for v2005")
		soapAction = trust2005Spec
		trustNamespace = "http://schemas.xmlsoap.org/ws/2005/02/trust"
		keyType = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey"
		requestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue"
	} else {
		log.Trace("Building WS-Trust token request for v1.3")
		soapAction = trust13Spec
		trustNamespace = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
		keyType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
		requestType = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
	}

	var envelope wsTrustTokenRequestEnvelope

	messageUUID := uuid.NewV4()

	envelope.S = "http://www.w3.org/2003/05/soap-envelope"
	envelope.Wsa = "http://www.w3.org/2005/08/addressing"
	envelope.Wsu = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"

	envelope.Header.Action.MustUnderstand = "1"
	envelope.Header.Action.Text = soapAction
	envelope.Header.MessageID.Text = "urn:uuid:" + messageUUID.String()
	envelope.Header.ReplyTo.Address.Text = "http://www.w3.org/2005/08/addressing/anonymous"
	envelope.Header.To.MustUnderstand = "1"
	envelope.Header.To.Text = wte.url

	// note: uuid on golang: https://stackoverflow.com/questions/15130321/is-there-a-method-to-generate-a-uuid-with-go-language
	// using "github.com/twinj/uuid"

	if authType == msalbase.AuthorizationTypeUsernamePassword {

		endpointUUID := uuid.NewV4()

		var trustID string
		if wte.endpointVersion == Trust2005 {
			trustID = "UnPwSecTok2005-" + endpointUUID.String()
		} else {
			trustID = "UnPwSecTok13-" + endpointUUID.String()
		}

		envelope.Header.Security.MustUnderstand = "1"
		envelope.Header.Security.Wsse = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
		envelope.Header.Security.Timestamp.ID = "MSATimeStamp"
		envelope.Header.Security.Timestamp.Created.Text = buildTimeString(createdTime)
		envelope.Header.Security.Timestamp.Expires.Text = buildTimeString(expiresTime)
		envelope.Header.Security.UsernameToken.ID = trustID
		envelope.Header.Security.UsernameToken.Username.Text = username
		envelope.Header.Security.UsernameToken.Password.Text = password
	}

	envelope.Body.RequestSecurityToken.Wst = trustNamespace
	envelope.Body.RequestSecurityToken.AppliesTo.Wsp = "http://schemas.xmlsoap.org/ws/2004/09/policy"
	envelope.Body.RequestSecurityToken.AppliesTo.EndpointReference.Address.Text = cloudAudienceURN
	envelope.Body.RequestSecurityToken.KeyType.Text = keyType
	envelope.Body.RequestSecurityToken.RequestType.Text = requestType

	output, err := xml.Marshal(envelope)
	if err != nil {
		return "", err
	}

	log.Trace(string(output))

	return string(output), nil
}

func (wte *WsTrustEndpoint) BuildTokenRequestMessageWIA(cloudAudienceURN string) (string, error) {
	return wte.buildTokenRequestMessage(msalbase.AuthorizationTypeWindowsIntegratedAuth, cloudAudienceURN, "", "")
}

func (wte *WsTrustEndpoint) BuildTokenRequestMessageUsernamePassword(cloudAudienceURN string, username string, password string) (string, error) {
	return wte.buildTokenRequestMessage(msalbase.AuthorizationTypeUsernamePassword, cloudAudienceURN, username, password)
}

func (wte *WsTrustEndpoint) GetURL() string {
	return wte.url
}

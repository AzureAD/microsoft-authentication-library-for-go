// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// OIDs used when building the IMDSv2 certificate signing request.
var (
	oidCommonName      = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidDomainComponent = asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}

	// oidCuid is the Microsoft-specific CSR attribute that carries the compute
	// unique identifier. IMDS uses it to tie the request to this VM or VMSS.
	oidCuid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 90, 2, 10}

	oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidMGF1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// csrKeyBits is the RSA key size IMDS expects for the binding key.
const csrKeyBits = 2048

// pkcs10Attribute is a single CSR attribute: an OID plus a SET of values.
type pkcs10Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// certificationRequestInfo is the to-be-signed half of a PKCS#10 request.
//
// Attributes is tagged [0] IMPLICIT. Implicit tagging replaces the universal
// SET tag, so the encoding is identical to the "[0] IMPLICIT SET OF Attribute"
// the specification calls for.
type certificationRequestInfo struct {
	Version       int
	Subject       asn1.RawValue
	SubjectPKInfo asn1.RawValue
	Attributes    []pkcs10Attribute `asn1:"tag:0"`
}

type certificationRequest struct {
	Info               asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

// rsaPSSParams mirrors RSASSA-PSS-params from RFC 4055 for SHA-256 with an
// equal-length salt. Every field is explicitly tagged because each one carries
// a DEFAULT that refers to SHA-1.
//
// TrailerField is optional with a default so that the value 1 is left out of
// the encoding. DER requires a field equal to its DEFAULT to be omitted, and
// IMDS rejects a request that spells it out.
type rsaPSSParams struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MaskGen      pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"explicit,tag:3,optional,default:1"`
}

// pssSHA256AlgorithmIdentifier returns the AlgorithmIdentifier describing
// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32 byte salt.
//
// The SHA-256 identifier carries no parameters at all. RFC 4055 section 2.1
// allows either an absent parameter or an explicit NULL, but it says a sender
// SHOULD omit it, and that is what IMDS accepts.
func pssSHA256AlgorithmIdentifier() (pkix.AlgorithmIdentifier, error) {
	sha256AlgID := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	sha256DER, err := asn1.Marshal(sha256AlgID)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("managedidentity: marshaling SHA-256 algorithm identifier: %w", err)
	}

	params := rsaPSSParams{
		Hash: sha256AlgID,
		MaskGen: pkix.AlgorithmIdentifier{
			Algorithm:  oidMGF1,
			Parameters: asn1.RawValue{FullBytes: sha256DER},
		},
		SaltLength:   sha256.Size,
		TrailerField: 1,
	}
	paramsDER, err := asn1.Marshal(params)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("managedidentity: marshaling RSASSA-PSS parameters: %w", err)
	}

	return pkix.AlgorithmIdentifier{
		Algorithm:  oidRSASSAPSS,
		Parameters: asn1.RawValue{FullBytes: paramsDER},
	}, nil
}

// createCSR builds a PKCS#10 certificate signing request for the IMDSv2
// binding certificate and returns it as unpadded single-line base64 DER, which
// is the shape the /issuecredential endpoint accepts.
//
// The subject is "CN={clientID}, DC={tenantID}" and the request carries the
// compute unique identifier as a custom attribute. The request is self-signed
// with RSA-PSS over SHA-256 using signer, which on Windows is a KeyGuard key
// whose private material never leaves VBS isolation.
func createCSR(signer crypto.Signer, clientID, tenantID string, cuid cuidInfo) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("managedidentity: a signer is required to build a CSR")
	}
	pub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("managedidentity: the binding key must be an RSA key, got %T", signer.Public())
	}
	if bits := pub.N.BitLen(); bits != csrKeyBits {
		return "", fmt.Errorf("managedidentity: the binding key must be %d bits, got %d", csrKeyBits, bits)
	}
	if clientID == "" || tenantID == "" {
		return "", fmt.Errorf("managedidentity: IMDS returned metadata without a client ID or tenant ID")
	}
	if cuid.VMID == "" && cuid.VMSSID == "" {
		return "", fmt.Errorf("managedidentity: IMDS returned metadata without a vmId or vmssId")
	}

	// RFC 4514 renders an RDNSequence in reverse, so encoding DC before CN
	// yields the string form "CN={clientID}, DC={tenantID}".
	//
	// The domain component is an IA5String. RFC 4519 defines it that way, and
	// it is what MSAL .NET puts on the wire, so the value is encoded
	// explicitly: a plain Go string would become a PrintableString and IMDS
	// rejects the resulting subject.
	dcValue, err := asn1.MarshalWithParams(tenantID, "ia5")
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the CSR domain component: %w", err)
	}
	subjectDER, err := asn1.Marshal(pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{{
			Type:  oidDomainComponent,
			Value: asn1.RawValue{FullBytes: dcValue},
		}},
		pkix.RelativeDistinguishedNameSET{{
			Type:  oidCommonName,
			Value: clientID,
		}},
	})
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the CSR subject: %w", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the binding public key: %w", err)
	}

	cuidJSON, err := json.Marshal(cuid)
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the compute identifier: %w", err)
	}
	cuidValue, err := asn1.MarshalWithParams(string(cuidJSON), "utf8")
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the compute identifier attribute: %w", err)
	}

	info := certificationRequestInfo{
		Version:       0,
		Subject:       asn1.RawValue{FullBytes: subjectDER},
		SubjectPKInfo: asn1.RawValue{FullBytes: spkiDER},
		Attributes: []pkcs10Attribute{{
			Type:   oidCuid,
			Values: []asn1.RawValue{{FullBytes: cuidValue}},
		}},
	}
	infoDER, err := asn1.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the CSR body: %w", err)
	}

	sigAlg, err := pssSHA256AlgorithmIdentifier()
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(infoDER)
	signature, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return "", fmt.Errorf("managedidentity: signing the CSR: %w", err)
	}

	csrDER, err := asn1.Marshal(certificationRequest{
		Info:               asn1.RawValue{FullBytes: infoDER},
		SignatureAlgorithm: sigAlg,
		Signature:          asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return "", fmt.Errorf("managedidentity: marshaling the CSR: %w", err)
	}

	// IMDS wants raw base64 DER: no PEM armor and no line breaks.
	return base64.StdEncoding.EncodeToString(csrDER), nil
}

// verifyCSRSignature re-verifies a generated CSR against the public key that
// signed it. It exists so the signing path can be exercised in tests without a
// live IMDS, and so a malfunctioning hardware signer is caught locally rather
// than as an opaque rejection from IMDS.
func verifyCSRSignature(csrBase64 string, pub *rsa.PublicKey) error {
	der, err := base64.StdEncoding.DecodeString(csrBase64)
	if err != nil {
		return fmt.Errorf("managedidentity: decoding the CSR: %w", err)
	}
	var req certificationRequest
	if rest, err := asn1.Unmarshal(der, &req); err != nil {
		return fmt.Errorf("managedidentity: parsing the CSR: %w", err)
	} else if len(rest) != 0 {
		return fmt.Errorf("managedidentity: %d trailing bytes after the CSR", len(rest))
	}
	if !req.SignatureAlgorithm.Algorithm.Equal(oidRSASSAPSS) {
		return fmt.Errorf("managedidentity: the CSR is not signed with RSASSA-PSS")
	}
	digest := sha256.Sum256(req.Info.FullBytes)
	return rsa.VerifyPSS(pub, crypto.SHA256, digest[:], req.Signature.Bytes, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	})
}

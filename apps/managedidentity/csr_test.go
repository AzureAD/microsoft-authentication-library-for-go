// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package managedidentity

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

const (
	testCSRClientID = "5c8b5b0a-1f8b-4a1e-9c4a-3f3a1b2c3d4e"
	testCSRTenantID = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	testCSRVMID     = "43ea1f9f-8c9e-4bdd-b5ef-265fbcc94c09"
)

func testCSRKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, csrKeyBits)
	if err != nil {
		t.Fatalf("generating a test key: %v", err)
	}
	return key
}

// TestCSRMatchesDotNetEncoding pins the parts of the request that are byte
// exact regardless of the key, because IMDS rejected earlier encodings that
// every Go parser accepted.
//
// The expected bytes were taken from a CSR produced by MSAL .NET for the same
// inputs and compared byte for byte. Three of these deviations were live bugs:
// an explicit trailerField, which DER forbids because it repeats the DEFAULT,
// and a NULL parameter on each of the two SHA-256 identifiers, which RFC 4055
// says a sender should leave out. crypto/x509 accepts all three, so only a
// fixed encoding catches them.
func TestCSRMatchesDotNetEncoding(t *testing.T) {
	const wantSigAlg = "303d06092a864886f70d01010a3030" +
		"a00d300b0609608648016503040201" +
		"a11a301806092a864886f70d010108300b0609608648016503040201" +
		"a203020120"

	key := testCSRKey(t)
	csr, err := createCSR(key, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID})
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(csr)
	if err != nil {
		t.Fatalf("the CSR is not valid base64: %v", err)
	}

	var req certificationRequest
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		t.Fatalf("parsing the CSR: %v", err)
	}
	sigAlgDER, err := asn1.Marshal(req.SignatureAlgorithm)
	if err != nil {
		t.Fatalf("re-marshaling the signature algorithm: %v", err)
	}
	if got := hex.EncodeToString(sigAlgDER); got != wantSigAlg {
		t.Errorf("signature algorithm DER\n got %s\nwant %s", got, wantSigAlg)
	}

	// The domain component must be an IA5String. A plain Go string encodes as
	// a PrintableString, which IMDS rejects.
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("crypto/x509 rejected the CSR: %v", err)
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(parsed.RawSubject, &rdns); err != nil {
		t.Fatalf("parsing the subject: %v", err)
	}
	var checkedDC bool
	for _, rdn := range rdns {
		for _, atv := range rdn {
			if !atv.Type.Equal(oidDomainComponent) {
				continue
			}
			checkedDC = true
			raw, ok := atv.Value.(string)
			if !ok {
				t.Fatalf("the domain component parsed as %T, want a string", atv.Value)
			}
			if raw != testCSRTenantID {
				t.Errorf("DC = %q, want %q", raw, testCSRTenantID)
			}
		}
	}
	if !checkedDC {
		t.Fatal("the subject has no domain component")
	}
	if !bytes.Contains(parsed.RawSubject, append([]byte{byte(asn1.TagIA5String), byte(len(testCSRTenantID))}, testCSRTenantID...)) {
		t.Errorf("the domain component is not encoded as an IA5String: % x", parsed.RawSubject)
	}
}

// TestCreateCSRIsValidPKCS10 checks the hand-rolled DER against an independent
// parser. crypto/x509 did not produce these bytes, so its acceptance is real
// evidence that the encoding is a well-formed PKCS#10 request and not merely
// self-consistent.
func TestCreateCSRIsValidPKCS10(t *testing.T) {
	key := testCSRKey(t)
	csr, err := createCSR(key, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID})
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}

	der, err := base64.StdEncoding.DecodeString(csr)
	if err != nil {
		t.Fatalf("the CSR is not valid base64: %v", err)
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("crypto/x509 rejected the CSR: %v", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		t.Fatalf("crypto/x509 rejected the CSR signature: %v", err)
	}
	if parsed.SignatureAlgorithm != x509.SHA256WithRSAPSS {
		t.Errorf("signature algorithm = %v, want %v", parsed.SignatureAlgorithm, x509.SHA256WithRSAPSS)
	}
	if got := parsed.Subject.CommonName; got != testCSRClientID {
		t.Errorf("CN = %q, want %q", got, testCSRClientID)
	}
	// RFC 4514 renders an RDNSequence in reverse, so the string form must put
	// CN ahead of DC even though DC is encoded first.
	if got := parsed.Subject.String(); !strings.HasPrefix(got, "CN="+testCSRClientID) {
		t.Errorf("subject = %q, want it to start with CN=%s", got, testCSRClientID)
	}
	// The tenant is asserted through the parsed RDNs rather than the string
	// form: crypto/x509 has no short name for domainComponent and renders it as
	// a numeric OID with a hex value, whereas .NET renders it as "DC=".
	var gotDC string
	for _, atv := range parsed.Subject.Names {
		if atv.Type.Equal(oidDomainComponent) {
			gotDC, _ = atv.Value.(string)
		}
	}
	if gotDC != testCSRTenantID {
		t.Errorf("domainComponent = %q, want %q", gotDC, testCSRTenantID)
	}
	if parsed.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("public key algorithm = %v, want RSA", parsed.PublicKeyAlgorithm)
	}
	pub, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *rsa.PublicKey", parsed.PublicKey)
	}
	if pub.N.Cmp(key.N) != 0 {
		t.Error("the CSR carries a different public key than the one that signed it")
	}
	if got := pub.N.BitLen(); got != csrKeyBits {
		t.Errorf("key size = %d bits, want %d", got, csrKeyBits)
	}
}

// TestCreateCSRStructure walks the DER the same way the MSAL .NET CsrValidator
// does, so a divergence from the shape IMDS expects is caught here.
func TestCreateCSRStructure(t *testing.T) {
	key := testCSRKey(t)
	cuid := cuidInfo{VMID: testCSRVMID, VMSSID: ""}
	csr, err := createCSR(key, testCSRClientID, testCSRTenantID, cuid)
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(csr)
	if err != nil {
		t.Fatalf("decoding the CSR: %v", err)
	}

	var req certificationRequest
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		t.Fatalf("parsing the CSR: %v", err)
	}
	if len(rest) != 0 {
		t.Errorf("found %d trailing bytes after the CSR", len(rest))
	}
	if !req.SignatureAlgorithm.Algorithm.Equal(oidRSASSAPSS) {
		t.Errorf("signature algorithm OID = %v, want %v", req.SignatureAlgorithm.Algorithm, oidRSASSAPSS)
	}

	var info certificationRequestInfo
	if _, err := asn1.Unmarshal(req.Info.FullBytes, &info); err != nil {
		t.Fatalf("parsing the CSR body: %v", err)
	}
	if info.Version != 0 {
		t.Errorf("version = %d, want 0", info.Version)
	}
	if len(info.Attributes) != 1 {
		t.Fatalf("attribute count = %d, want 1", len(info.Attributes))
	}
	attr := info.Attributes[0]
	if !attr.Type.Equal(oidCuid) {
		t.Errorf("attribute OID = %v, want %v", attr.Type, oidCuid)
	}
	if len(attr.Values) != 1 {
		t.Fatalf("attribute value count = %d, want 1", len(attr.Values))
	}

	var gotJSON string
	if _, err := asn1.UnmarshalWithParams(attr.Values[0].FullBytes, &gotJSON, "utf8"); err != nil {
		t.Fatalf("the CUID attribute is not a UTF8String: %v", err)
	}
	// Pinned as a literal rather than round-tripped through json.Marshal: IMDS
	// validates this string against the cuId it handed out, so comparing the
	// encoder with itself would accept any shape it happens to produce. A
	// standalone VM's cuId carries no vmssId member, and emitting an empty one
	// makes the service reject the CSR.
	wantJSON := `{"vmId":"` + testCSRVMID + `"}`
	if gotJSON != wantJSON {
		t.Errorf("CUID attribute = %s, want %s", gotJSON, wantJSON)
	}
}

// TestCreateCSRCuidOmitsAbsentMembers pins the exact JSON for each shape of cuId
// IMDS can hand out. The value is echoed inside the signed attribute and the
// service compares it with what it issued, so an extra empty member is not
// cosmetic: it is the difference between a certificate and a 400.
func TestCreateCSRCuidOmitsAbsentMembers(t *testing.T) {
	key := testCSRKey(t)
	for _, test := range []struct {
		name string
		cuid cuidInfo
		want string
	}{
		{"standalone VM", cuidInfo{VMID: testCSRVMID}, `{"vmId":"` + testCSRVMID + `"}`},
		{"scale set member", cuidInfo{VMSSID: "scale-set-1"}, `{"vmssId":"scale-set-1"}`},
		{"both", cuidInfo{VMID: testCSRVMID, VMSSID: "scale-set-1"}, `{"vmId":"` + testCSRVMID + `","vmssId":"scale-set-1"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			csr, err := createCSR(key, testCSRClientID, testCSRTenantID, test.cuid)
			if err != nil {
				t.Fatalf("createCSR: %v", err)
			}
			der, err := base64.StdEncoding.DecodeString(csr)
			if err != nil {
				t.Fatalf("decoding the CSR: %v", err)
			}
			var req certificationRequest
			if _, err := asn1.Unmarshal(der, &req); err != nil {
				t.Fatalf("parsing the CSR: %v", err)
			}
			var info certificationRequestInfo
			if _, err := asn1.Unmarshal(req.Info.FullBytes, &info); err != nil {
				t.Fatalf("parsing the CSR body: %v", err)
			}
			var gotJSON string
			if _, err := asn1.UnmarshalWithParams(info.Attributes[0].Values[0].FullBytes, &gotJSON, "utf8"); err != nil {
				t.Fatalf("the CUID attribute is not a UTF8String: %v", err)
			}
			if gotJSON != test.want {
				t.Errorf("CUID attribute = %s, want %s", gotJSON, test.want)
			}
		})
	}
}

// TestCreateCSRIsSingleLineBase64 pins the wire format: IMDS wants raw base64
// DER with no PEM armor and no line breaks.
func TestCreateCSRIsSingleLineBase64(t *testing.T) {
	key := testCSRKey(t)
	csr, err := createCSR(key, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID})
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}
	for _, bad := range []string{"\n", "\r", " ", "-----BEGIN", "-----END"} {
		if strings.Contains(csr, bad) {
			t.Errorf("the CSR contains %q, but IMDS expects unarmored single-line base64", bad)
		}
	}
}

func TestVerifyCSRSignature(t *testing.T) {
	key := testCSRKey(t)
	csr, err := createCSR(key, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID})
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}
	if err := verifyCSRSignature(csr, &key.PublicKey); err != nil {
		t.Errorf("verifyCSRSignature: %v", err)
	}
	other := testCSRKey(t)
	if err := verifyCSRSignature(csr, &other.PublicKey); err == nil {
		t.Error("verifyCSRSignature accepted a signature made by a different key")
	}
}

// brokenSigner returns a signature that is well-formed but wrong, standing in
// for a hardware signer that is present but misbehaving.
type brokenSigner struct{ pub *rsa.PublicKey }

func (b brokenSigner) Public() crypto.PublicKey { return b.pub }
func (b brokenSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, b.pub.Size()), nil
}

// TestCreateCSRDetectsBadSigner is the mutation check for the signing path: if
// the signature were never verified, a broken signer would go unnoticed.
func TestCreateCSRDetectsBadSigner(t *testing.T) {
	key := testCSRKey(t)
	csr, err := createCSR(brokenSigner{pub: &key.PublicKey}, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID})
	if err != nil {
		t.Fatalf("createCSR: %v", err)
	}
	if err := verifyCSRSignature(csr, &key.PublicKey); err == nil {
		t.Error("a CSR signed with a bogus signature was accepted")
	}
	der, err := base64.StdEncoding.DecodeString(csr)
	if err != nil {
		t.Fatalf("decoding the CSR: %v", err)
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing the CSR: %v", err)
	}
	if err := parsed.CheckSignature(); err == nil {
		t.Error("crypto/x509 accepted a CSR with a bogus signature")
	}
}

func TestCreateCSRRejectsBadInput(t *testing.T) {
	key := testCSRKey(t)
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating a 1024 bit key: %v", err)
	}

	tests := []struct {
		name     string
		signer   crypto.Signer
		clientID string
		tenantID string
		cuid     cuidInfo
	}{
		{"nil signer", nil, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID}},
		{"wrong key size", small, testCSRClientID, testCSRTenantID, cuidInfo{VMID: testCSRVMID}},
		{"no client ID", key, "", testCSRTenantID, cuidInfo{VMID: testCSRVMID}},
		{"no tenant ID", key, testCSRClientID, "", cuidInfo{VMID: testCSRVMID}},
		{"no compute identifier", key, testCSRClientID, testCSRTenantID, cuidInfo{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := createCSR(test.signer, test.clientID, test.tenantID, test.cuid); err == nil {
				t.Error("createCSR accepted invalid input")
			}
		})
	}
}

// TestCreateCSRAcceptsVMSSOnly covers a scale set member, where IMDS reports a
// vmssId and no vmId.
func TestCreateCSRAcceptsVMSSOnly(t *testing.T) {
	key := testCSRKey(t)
	if _, err := createCSR(key, testCSRClientID, testCSRTenantID, cuidInfo{VMSSID: "some-scale-set"}); err != nil {
		t.Errorf("createCSR rejected a scale set compute identifier: %v", err)
	}
}

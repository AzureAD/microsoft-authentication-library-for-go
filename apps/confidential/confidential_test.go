package confidential

import "testing"

func TestCertFromPEM(t *testing.T) {
	// pem is generated from: openssl req -newkey rsa:2048 -new -nodes -x509 -keyout key.pem -out cert.pem
	// This cert is not used anywhere.
	var pemData = []byte(`
-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDNgteZ+lJH4zANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJ1
czAeFw0yMTAxMDQyMzQzNDVaFw0yMTAyMDMyMzQzNDVaMA0xCzAJBgNVBAYTAnVz
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1r58wq7JQxM12viLNbdG
fFizeVQwWRwrx/4CH3kU8jjGovbhkvC/uLWqVGchgATThhGkvNrA92WvdkVwsZMk
Qf7ZnTA7kemo4VFtgo5XCGEej9gOTW13Evdc/0Flip+RXl3h3Q6BbbB9IFE0c6cS
3i/v/t8KGpVYQHQzBwTcYehM6eDO8ZjUyUUcJOMXdMCctamig7fMGlziKFahn4dX
JoiiK4oNKE9okXIAXCTbVkAxxH0hD+5XH1nn5LJnHe0e5DflI3YIiPgmRL5uC89K
XqmYCKWrq5z2D5k+5fQLmbOcxErBcFCh8hA+Xu0RLT4BHPEgc6iVIqxL4CZi/cke
uwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAAyDbm0Fda0/vY6ZVDML2IbGWbro1w
nWYNw6wclNU6sx1oeG/k/y2ni7NImPpbFN+594WS6rYHgFdROfeuNgGnjgQCJogk
+8ouf1R6vFMUAScWeSaFnZmBEgwofWsnIcUKkbDIXbpRhMrkNEcY09VgjmCKhspQ
iX2bJQTj49XBac9tBaJJYDZ4HgkO4nU7QeEPpvwlELZFoZZXtd3fan+VUyFS2a9n
gkAMDYoQPGN4tyGFabWws/GlMxelWvqUzpQKmeRPVz+cij75l8eKThEiu0zbjOTD
Gq81BcY61SPqN02zoPCtqZ/zU6HhaL3x7zUuzhLhNoh83A43UVYEoOOf
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDWvnzCrslDEzXa
+Is1t0Z8WLN5VDBZHCvH/gIfeRTyOMai9uGS8L+4tapUZyGABNOGEaS82sD3Za92
RXCxkyRB/tmdMDuR6ajhUW2CjlcIYR6P2A5NbXcS91z/QWWKn5FeXeHdDoFtsH0g
UTRzpxLeL+/+3woalVhAdDMHBNxh6Ezp4M7xmNTJRRwk4xd0wJy1qaKDt8waXOIo
VqGfh1cmiKIrig0oT2iRcgBcJNtWQDHEfSEP7lcfWefksmcd7R7kN+UjdgiI+CZE
vm4Lz0peqZgIpaurnPYPmT7l9AuZs5zESsFwUKHyED5e7REtPgEc8SBzqJUirEvg
JmL9yR67AgMBAAECggEAAQ/IBh5fGFnL9l0sMwPI8Wxu1ra31njxLnfvAsDSfbAS
K1QVIWjXSc58HRa1b7CWax9DNTvPoGl8SJVnTTlxAHKGGOTYJoyFLTf91ptlisEQ
KZ3j1DYqVImsiAaGvfyz90d3imQ795Lby4EbRUcaLMcH5LatkhwS556rcelwPXuq
M43XaZu5Es4pG0EmzfXplO/awt5HdUDPEAY3yw7QH8D1/l/toLPyiFv37RezkVK9
ffcUQpH7uH000Gja+JSEHgpWZhE96ac6H0zBtlM1VkMtfBuczz5tkKN/p70fhr8T
ZXARZqIaF4vx7RkBBzCfhvrgGqxXMuvTaW6N4RDWYQKBgQD1iZ7/xr9qy4cPFSOt
yBnG5cE6wC7wP8qgr0N7MgAii5OZgx6rtfGIVJDY58CFijnT8jZ5pjNS3p7j/Rzp
lQJMIwC5kIe/7FU7nmE3ko7Wg+bpd8iWLLIi/QWVFLbS7qVmulTc+CEXWyhAiI2u
RL/1APjIDFKp9gqtKmwb9erxDwKBgQDf5PbGHuPv5RBLJz9du+M/BIBY+HDltG89
p3huHHTjkJ5R38oximf2HnV4ygT/p2+ZUD6TJZZw6qou3/GiU5gZbRpg+4LXtQUR
vV+S2n/t86NG1YcGmM29r8LWqrK9gxLW0X62Fpps16rHSP7kVc4SvmrYwqNzqKlC
D9QbFYYflQKBgQCKEVzrDuNMNi43+PcbHU4BXeiOFMtQJU7XlDYp7C/PPRU+WVDB
1Yl/062vioHjlZp259hiB2cMzkoigY3kevnTvksGDZOIBGjZIXIhQbQ4Q+twlP6i
E3gH3Kdq8T7s1W0EmvplVtGkxImZ4C9rMxWNu4IpW2SQVd4jCZvJDTuTWQKBgQCn
LGjuCYacSubdlpKDxJSrKwtCY0641P7yhCcx4GGOwR7Vd0mbsAJsDNYduIn+8eAs
E3SFnl00NqOXmHLth4lcAtDddS5/LZR5aHMCTc+TtoVFkI3faRzF84SBkLchNctN
RuNbxojLmETVxDU9/Kt/51oUO1CcPWUUBImVJ38b+QKBgQCTbi0nS0n8kC7nlXWN
QtPcf4UraJAxv1DGq4lnJ8AHSZqqkP5fyjfknSw5ExOPDg4mEHhnnpsvwJuSX00d
UYUN2ZJXPZeaO0HmbYZ3/vC9bo6KW95PhidEUQpGlKrFY342khjQHJtH67YUThwU
lQFhpxvPgPNBuxVRnsxoH/sLOA==
-----END PRIVATE KEY-----	
`)

	certs, key, err := CertFromPEM(pemData, "")
	if err != nil {
		t.Fatalf("TestCertFromPEM: got err == %s, want err == nil", err)
	}
	if len(certs) != 1 {
		t.Fatalf("TestCertFromPEM: got %d certs, want 1 cert", len(certs))
	}
	if key == nil {
		t.Fatalf("TestCertFromPEM: got nil key, want key != nil")
	}
}

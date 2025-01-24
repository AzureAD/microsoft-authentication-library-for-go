package managedidentity

import (
	"crypto/x509"
	"fmt"
	"testing"
)

const testThumbprint = "A2B8C5D6E8F4C9D0A1234B1F8E9D0C4E9F1111FF"

var testCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALFX5MseFhfxMA0GCSqGSIb3DQEBBQUAMCUxIzAhBgNV
BAMMGm15Y29tcGFueS5leGFtcGxlLmNvbTAeFw0yMDAxMjExODI4MjZaFw0yMDAz
MDEwMDAwMDBaMCkxIzAhBgNVBAMMGm15Y29tcGFueS5leGFtcGxlLmNvbTAwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEIAwIHZcjcY1jQhBeHk1u7q8G+90Hv8Gr+V
6tOdQzVdVg8W5UvWXtLwaC5JXy1FdQNvQVeT+Hfuj3n6pBaY+tnKMU8XlTGyEqjl
OryPyW9Pz4hXw7THTSFLfXKZigfHpcwD/JqAtHh1KnwYr9oWAt7TdmHj6DddK2ap
zTbEoPT/jg49lHo4blLvHm5WG6YO0Rb8z1smIVOTj12gd4E4Fw4Wz1O6roHxtQfM
rwO+nmAoD7R4fNGP+6g9YlY2l97lNcs0xhZcMOw0K0Hj5uJbIzkRkZoVjL3XqT19
dhtAqkN9kqTO26b8A9jpfW58brmjOhsDNiW2YyopkZvxlqsvYH2sL67vsxyxuCmK
H6ne9PdyJil4FJ7sS3SiXUdxrxZ8t4Vwr7lo3BhzTkMjDZhRsO71g+mPH1xyk8eV
pHmj0jb9CBE+Q+S+/AKf9EGy2YHtfe71+fUecxguyFcTmuCo1Sm7eO5iCKHfUsqA
lX6R+NlwFgL0jmbTRgHkc59NT7WYx+DFJFXq9h2Kf5XKz5rjcTbntON0smfuGFzD
TkTf7CmFzW1F9lsbT/Jr8Xg2b13rkMCkr34d1+RfDDi2Jx0wUs0cS5d74jFSdXiq
tXZacg0Fv1u0Yps9rxYYGFwt6rO5asDe+3z/sOGuo8hTb/M5Pzxjq9dtDR1BxV1f
DeHj0qg1L0sUSwG6zrd2pXs=
-----END CERTIFICATE-----
`)

func TestSslCertificateChecker(t *testing.T) {
	// Set the environment variable for thumbprint
	t.Setenv(identityServerThumbprintEnvVar, testThumbprint)

	tests := []struct {
		name        string
		rawCerts    [][]byte
		expectedErr error
	}{
		{
			name: "valid certificate with matching thumbprint",
			rawCerts: [][]byte{
				testCert,
			},
			expectedErr: nil,
		},
		{
			name: "invalid thumbprint",
			rawCerts: [][]byte{
				testCert, // This is the certificate we will validate
			},
			expectedErr: fmt.Errorf("certificate thumbprint does not match the expected value"),
		},
		{
			name: "no thumbprint set in environment",
			rawCerts: [][]byte{
				testCert,
			},
			expectedErr: fmt.Errorf("identity server thumbprint is not set in environment variables"),
		},
		{
			name:        "empty certs",
			rawCerts:    nil,
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sslCertificateChecker(tt.rawCerts, nil)
			if tt.expectedErr == nil {
				// No error should be returned
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				// Error should be returned
				if err == nil {
					t.Fatalf("expected error, got nil")
				} else if err.Error() != tt.expectedErr.Error() {
					t.Fatalf("expected error: %v, got: %v", tt.expectedErr.Error(), err.Error())
				}
			}
		})
	}
}

func TestGetCertThumbprint(t *testing.T) {
	cert, err := x509.ParseCertificate(testCert)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	expectedThumbprint := "A2B8C5D6E8F4C9D0A1234B1F8E9D0C4E9F1111FF"
	actualThumbprint := getCertThumbprint(cert)
	if actualThumbprint != expectedThumbprint {
		t.Fatalf("expected thumbprint %s, got %s", expectedThumbprint, actualThumbprint)
	}
}

func TestNewHTTPClientWithCustomCertValidation(t *testing.T) {
	client, err := NewHTTPClientWithCustomCertValidation()
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}
	if client == nil {
		t.Fatalf("client is nil")
	}
	if client.Transport == nil {
		t.Fatalf("client.Transport is nil")
	}
}

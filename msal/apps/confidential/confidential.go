/*
Package confidential provides a client for authentication of "confidential" applications.
A "confidential" application is defined as an app that run on servers. They're considered
difficult to access, and for that reason capable of keeping an application secret.
Confidential clients can hold configuration-time secrets.
*/
package confidential

import (
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/internal/msalbase"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/apps/internal/client"
	"github.com/AzureAD/microsoft-authentication-library-for-go/msal/cache"
	"github.com/google/uuid"

	jwt "github.com/dgrijalva/jwt-go"
)

/*
Design note:

confidential.Client uses client.Base as an embedded type. client.Base statically assigns its attributes
during creation. As it doesn't have any pointers in it, anything borrowed from it, such as
Base.AuthParams is a copy that is free to be manipulated here.

C# people: This uses x509.Certificates and private keys. x509 does not store private keys. .Net
has some x509.Certificate2 thing that has private keys, but that is just some bullcrap that .Net
added, it doesn't exist in real life.  Seriously, "x509.Certificate2", bahahahaha.  As such I've
put some decoders from certs into here.
*/

// TODO(msal): This should have example code for each method on client using Go's example doc framework.
// base usage details should be includee in the package documentation.

// AcquireTokenByAuthCodeOptions contains the optional parameters used to acquire an access token using the authorization code flow.
type AcquireTokenByAuthCodeOptions struct {
	Code          string
	CodeChallenge string
}

// CertFromPEM converts a PEM file (.pem or .key) for use with NewCredFromCert(). The file
// must have the public certificate and the private key encoded. The private key must be encoded
// in PKCS8 (not PKCS1). This is usally denoted by the section "PRIVATE KEY" (instead of PKCS1's
// "RSA PRIVATE KEY"). If a PEM block is encoded and password is not an empty string, it attempts
// to decrypt the PEM blocks using the password. This will return multiple x509 certificates,
// though this use case should have a single cert. Multiple certs are due to certificate
// chaining for use cases like TLS that sign from root to leaf.
func CertFromPEM(pemData []byte, password string) ([]*x509.Certificate, crypto.PrivateKey, error) {
	var certs []*x509.Certificate
	var priv crypto.PrivateKey
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if x509.IsEncryptedPEMBlock(block) {
			if password != "" {
				b, err := x509.DecryptPEMBlock(block, []byte(password))
				if err != nil {
					return nil, nil, fmt.Errorf("could not decrypt encrypted PEM block: %w", err)
				}
				block, _ = pem.Decode(b)
				if block == nil {
					return nil, nil, fmt.Errorf("encounter encrypted PEM block that did not decode")
				}
			} else {
				return nil, nil, fmt.Errorf("encountered encrypted PEM block, but password was not passed")
			}
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("block labelled 'CERTIFICATE' could not be pared by x509: %w", err)
			}
			certs = append(certs, cert)
		case "PRIVATE KEY":
			if priv != nil {
				return nil, nil, fmt.Errorf("found multiple blocks labelled 'PRIVATE KEY'")
			}

			var err error
			priv, err = parsePrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("could not decode private key: %w", err)
			}
		}
		pemData = rest
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found")
	}

	if priv == nil {
		return nil, nil, fmt.Errorf("no private key found")
	}

	return certs, priv, nil
}

// parsePrivateKey is based on https://gist.github.com/ukautz/cd118e298bbd8f0a88fc . I don't *think*
// we need to do the extra decoding in the example, but *maybe*?
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("problems decoding private key using PKCS8: %w", err)
	}
	return key, nil
}

// Credential represents the credential used in confidential client flows.
type Credential struct {
	// If secret is set, we use secret. Otherwise we are going to use assertion.
	// If assertion is not set, we are going to use cert + der to generate an assertion on first use.
	secret string

	cert *x509.Certificate
	key  crypto.PrivateKey

	mu        sync.Mutex
	assertion string
	expires   time.Time
}

// NewCredFromSecret creates a Credential from a secret.
func NewCredFromSecret(secret string) (*Credential, error) {
	if secret == "" {
		return nil, errors.New("secret can't be empty string")
	}
	return &Credential{secret: secret}, nil
}

// NewCredFromCert creates a Credential from an x509.Certificate and a PKCS8 DER encoded private key.
// CertFromPEM() can be used to get these values from a PEM file storing a PKCS8 private key.
func NewCredFromCert(cert *x509.Certificate, key crypto.PrivateKey) *Credential {
	return &Credential{cert: cert, key: key}
}

// jwt gets the jwt assertion when the credential is not using a secret.
func (c *Credential) jwt(authParams msalbase.AuthParametersInternal) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.expires.Before(time.Now()) && c.assertion != "" {
		return c.assertion, nil
	}
	expires := time.Now().Add(5 * time.Minute)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"aud": authParams.Endpoints.TokenEndpoint,
		"exp": strconv.FormatInt(expires.Unix(), 10),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": strconv.FormatInt(time.Now().Unix(), 10),
		"sub": authParams.ClientID,
	})
	token.Header = map[string]interface{}{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": base64.StdEncoding.EncodeToString(thumbprint(c.cert)),
	}

	var err error
	c.assertion, err = token.SignedString(c.key)
	if err != nil {
		return "", err
	}

	c.expires = expires
	return c.assertion, err
}

// thumbprint runs the asn1.Der bytes through sha1 for use in the x5t parameter of JWT.
// https://tools.ietf.org/html/rfc7517#section-4.8
func thumbprint(cert *x509.Certificate) []byte {
	a := sha1.Sum(cert.Raw)
	return a[:]
}

// Client is a representation of authentication client for confidential applications as defined in the
// package doc.
// For more information, visit https://docs.microsoft.com/azure/active-directory/develop/msal-client-applications
type Client struct {
	client.Base
	msalbase.ClientCredential
}

// Options are optional settings for New(). These options are set using various functions
// returning Option calls.
type Options struct {
	// Accessor controls cache persistence.
	// By default there is no cache persistence. This can be set using the Accessor() option.
	Accessor cache.ExportReplace

	// The host of the Azure Active Directory authority.
	// The default is https://login.microsoftonline.com/common. This can be changed using the
	// Authority() option.
	Authority string
}

func (o Options) validate() error {
	u, err := url.Parse(o.Authority)
	if err != nil {
		return fmt.Errorf("the Authority(%s) does not parse as a valid URL", o.Authority)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("the Authority(%s) does not appear to use https", o.Authority)
	}
	return nil
}

// Option is an optional argument to New().
type Option func(o *Options)

// Authority allows you to provide a custom authority for use in the client.
func Authority(authority string) Option {
	return func(o *Options) {
		o.Authority = authority
	}
}

// Accessor provides a cache accessor that will read and write to some externally managed cache
// that may or may not be shared with other applications.
func Accessor(accessor cache.ExportReplace) Option {
	return func(o *Options) {
		o.Accessor = accessor
	}
}

// New is the constructor for Client.
func New(clientID string, cred Credential, options ...Option) (Client, error) {
	opts := Options{
		Authority: client.AuthorityPublicCloud,
	}

	for _, o := range options {
		o(&opts)
	}
	if err := opts.validate(); err != nil {
		return Client{}, err
	}

	cred, err := createInternalClientCredential(clientCredential)
	if err != nil {
		return nil, err
	}

	clientApp, err := newClientApp(clientID, options.Authority)
	if err != nil {
		return nil, err
	}
	return &ConfidentialClientApplication{
		clientApplication: clientApp,
		clientCredential:  cred,
		token:             token,
	}, nil
}

// This is used to convert the user-facing client credential interface to the internal representation of a client credential
func createInternalClientCredential(interfaceCred ClientCredentialProvider) (msalbase.ClientCredential, error) {
	if interfaceCred.GetCredentialType() == msalbase.ClientCredentialSecret {
		return msalbase.CreateClientCredentialFromSecret(interfaceCred.GetSecret())

	}
	if interfaceCred.GetAssertion().ClientCertificate != nil {
		return msalbase.CreateClientCredentialFromCertificateObject(
			interfaceCred.GetAssertion().ClientCertificate), nil
	}
	return msalbase.CreateClientCredentialFromAssertion(interfaceCred.GetAssertion().ClientAssertionJWT)
}

// CreateAuthCodeURL creates a URL used to acquire an authorization code. Users need to call CreateAuthorizationCodeURLParameters and pass it in.
func (cca *ConfidentialClientApplication) CreateAuthCodeURL(ctx context.Context, authCodeURLParameters AuthorizationCodeURLParameters) (string, error) {
	return cca.clientApplication.createAuthCodeURL(ctx, authCodeURLParameters)
}

// AcquireTokenSilent acquires a token from either the cache or using a refresh token
// Users need to create an AcquireTokenSilentParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenSilent(ctx context.Context, scopes []string, options *AcquireTokenSilentOptions) (msalbase.AuthenticationResult, error) {
	silentParameters := CreateAcquireTokenSilentParameters(scopes)
	silentParameters.requestType = requests.RefreshTokenConfidential
	silentParameters.clientCredential = cca.clientCredential
	if options != nil {
		silentParameters.account = options.Account
	}
	return cca.clientApplication.acquireTokenSilent(ctx, silentParameters)
}

// AcquireTokenByAuthCode is a request to acquire a security token from the authority, using an authorization code.
// Users need to create an AcquireTokenAuthCodeParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByAuthCode(ctx context.Context, scopes []string, options *AcquireTokenByAuthCodeOptions) (msalbase.AuthenticationResult, error) {
	authCodeParams := createAcquireTokenAuthCodeParameters(scopes)
	authCodeParams.requestType = requests.AuthCodeConfidential
	authCodeParams.clientCredential = cca.clientCredential
	if options != nil {
		authCodeParams.Code = options.Code
		authCodeParams.CodeChallenge = options.CodeChallenge
	}
	return cca.clientApplication.acquireTokenByAuthCode(ctx, authCodeParams)

}

// AcquireTokenByClientCredential acquires a security token from the authority, using the client credentials grant.
// Users need to create an AcquireTokenClientCredentialParameters instance and pass it in.
func (cca *ConfidentialClientApplication) AcquireTokenByClientCredential(ctx context.Context, scopes []string) (msalbase.AuthenticationResult, error) {
	authParams := cca.clientApplication.clientApplicationParameters.createAuthenticationParameters()
	clientCredParams := createAcquireTokenClientCredentialParameters(scopes)
	clientCredParams.augmentAuthenticationParameters(&authParams)

	req := requests.CreateClientCredentialRequest(cca.clientApplication.webRequestManager, authParams, cca.clientCredential)
	return cca.clientApplication.executeTokenRequestWithCacheWrite(ctx, req, authParams)
}

// Accounts gets all the accounts in the token cache.
func (cca *ConfidentialClientApplication) Accounts() []msalbase.Account {
	return cca.clientApplication.getAccounts()
}

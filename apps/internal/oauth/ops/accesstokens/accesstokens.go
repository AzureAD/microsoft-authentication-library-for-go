// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/*
Package accesstokens exposes a REST client for querying backend systems to get various types of
access tokens (oauth) for use in authentication.

These calls are of type "application/x-www-form-urlencoded".  This means we use url.Values to
represent arguments and then encode them into the POST body message.  We receive JSON in
return for the requests.  The request definition is defined in https://tools.ietf.org/html/rfc7521#section-4.2 .
*/
package accesstokens

import (
	"context"
	"crypto"
	"crypto/rsa"

	/* #nosec */
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	msalerrors "github.com/AzureAD/microsoft-authentication-library-for-go/apps/errors"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/exported"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/authority"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/internal/grant"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/internal/oauth/ops/wstrust"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	grantType     = "grant_type"
	deviceCode    = "device_code"
	clientID      = "client_id"
	clientInfo    = "client_info"
	clientInfoVal = "1"
	username      = "username"
	password      = "password"
)

//go:generate stringer -type=AppType

// AppType is whether the authorization code flow is for a public or confidential client.
type AppType int8

const (
	// ATUnknown is the zero value when the type hasn't been set.
	ATUnknown AppType = iota
	// ATPublic indicates this if for the Public.Client.
	ATPublic
	// ATConfidential indicates this if for the Confidential.Client.
	ATConfidential
)

type urlFormCaller interface {
	URLFormCall(ctx context.Context, endpoint string, qv url.Values, resp interface{}) error
	// URLFormCallWithCertificate performs the request over a mutual-TLS connection presenting cert
	// as the client certificate. Used for mTLS proof-of-possession token requests.
	URLFormCallWithCertificate(ctx context.Context, endpoint string, qv url.Values, resp interface{}, cert *tls.Certificate) error
}

// DeviceCodeResponse represents the HTTP response received from the device code endpoint
type DeviceCodeResponse struct {
	authority.OAuthResponseBase

	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`

	AdditionalFields map[string]interface{}
}

// Convert converts the DeviceCodeResponse to a DeviceCodeResult
func (dcr DeviceCodeResponse) Convert(clientID string, scopes []string) DeviceCodeResult {
	expiresOn := time.Now().UTC().Add(time.Duration(dcr.ExpiresIn) * time.Second)
	return NewDeviceCodeResult(dcr.UserCode, dcr.DeviceCode, dcr.VerificationURL, expiresOn, dcr.Interval, dcr.Message, clientID, scopes)
}

// Credential represents the credential used in confidential client flows. This can be either
// a Secret or Cert/Key.
type Credential struct {
	// Secret contains the credential secret if we are doing auth by secret.
	Secret string

	// Cert is the public certificate, if we're authenticating by certificate.
	Cert *x509.Certificate
	// Key is the private key for signing, if we're authenticating by certificate.
	Key crypto.PrivateKey
	// X5c is the JWT assertion's x5c header value, required for SN/I authentication.
	X5c []string

	// AssertionCallback is a function provided by the application, if we're authenticating by assertion.
	AssertionCallback func(context.Context, exported.AssertionRequestOptions) (string, error)

	// SignedAssertionCallback is set when the application supplies its assertion together with the
	// certificate the assertion is bound to (confidential.NewCredFromSignedAssertionCallback).
	// AssertionCallback is always set alongside it and yields the same assertion, so every code path
	// that only knows about assertions keeps working unchanged; SignedAssertionCallback exists so the
	// mTLS proof-of-possession path can also obtain the binding certificate, which it needs before
	// the request body is built.
	SignedAssertionCallback func(context.Context, exported.AssertionRequestOptions) (exported.SignedAssertion, error)

	// TokenProvider is a function provided by the application that implements custom authentication
	// logic for a confidential client
	TokenProvider func(context.Context, exported.TokenProviderParameters) (exported.TokenProviderResult, error)
}

// assertionRequestOptions builds the options handed to an application-provided assertion callback.
func assertionRequestOptions(authParams authority.AuthParams) exported.AssertionRequestOptions {
	return exported.AssertionRequestOptions{
		ClientID:      authParams.ClientID,
		TokenEndpoint: authParams.Endpoints.TokenEndpoint,
		FMIPath:       authParams.ExtraBodyParameters["fmi_path"],
	}
}

// SignedAssertion invokes the credential's signed-assertion callback once and returns its result.
// It is the only caller of that callback: everything else goes through JWT, which replays whatever
// AssertionCallback yields. Callers must not invoke both for one token request.
func (c *Credential) SignedAssertion(ctx context.Context, authParams authority.AuthParams) (exported.SignedAssertion, error) {
	if c.SignedAssertionCallback == nil {
		return exported.SignedAssertion{}, errors.New("credential has no signed-assertion callback")
	}
	return c.SignedAssertionCallback(ctx, assertionRequestOptions(authParams))
}

// JWT gets the jwt assertion when the credential is not using a secret.
func (c *Credential) JWT(ctx context.Context, authParams authority.AuthParams) (string, error) {
	if c.AssertionCallback != nil {
		return c.AssertionCallback(ctx, assertionRequestOptions(authParams))
	}
	claims := jwt.MapClaims{
		"aud": authParams.Endpoints.TokenEndpoint,
		"exp": json.Number(strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)),
		"iss": authParams.ClientID,
		"jti": uuid.New().String(),
		"nbf": json.Number(strconv.FormatInt(time.Now().Unix(), 10)),
		"sub": authParams.ClientID,
	}

	isADFSorDSTS := authParams.AuthorityInfo.AuthorityType == authority.ADFS ||
		authParams.AuthorityInfo.AuthorityType == authority.DSTS

	var signingMethod jwt.SigningMethod = jwt.SigningMethodPS256
	thumbprintKey := "x5t#S256"

	if isADFSorDSTS {
		signingMethod = jwt.SigningMethodRS256
		thumbprintKey = "x5t"
	}

	// jwt's built-in RSA methods need a concrete *rsa.PrivateKey. Any other key is necessarily a
	// non-exportable one (KeyGuard/CNG/HSM) and has to sign through crypto.Signer.
	_, exportableRSA := c.Key.(*rsa.PrivateKey)

	// A non-exportable key can only ever be a crypto.Signer, which jwt's built-in RSA methods reject.
	// Wrap the method selected above in one that delegates to the signer. Alg() is unchanged, so the
	// assertion's wire format is too.
	if !exportableRSA {
		signer, ok := c.Key.(crypto.Signer)
		if !ok {
			return "", errors.New("this credential's private key must implement crypto.Signer to sign a client assertion")
		}
		if _, ok := signer.Public().(*rsa.PublicKey); !ok {
			// a credential can hold a signer for another key type because its certificate validates
			// against it, but the service only accepts RSA client assertions
			return "", errors.New("this credential's private key must be RSA to sign a client assertion")
		}
		method, err := newSignerMethod(signingMethod)
		if err != nil {
			return "", err
		}
		signingMethod = method
	}

	// build assembles and signs the assertion. It's a function because the fallback below has to
	// rebuild the whole thing rather than only re-sign: the algorithm determines the "alg" header,
	// which header carries the thumbprint, and which hash that thumbprint uses.
	build := func(method jwt.SigningMethod, thumbprintKey string) (string, error) {
		token := jwt.NewWithClaims(method, claims)
		token.Header = map[string]interface{}{
			"alg":         method.Alg(),
			"typ":         "JWT",
			thumbprintKey: base64.StdEncoding.EncodeToString(thumbprint(c.Cert, method.Alg())),
		}

		if authParams.SendX5C {
			token.Header["x5c"] = c.X5c
		}

		return token.SignedString(c.Key)
	}

	// A signer-backed key can live in hardware or behind a remote service, so signing may be slow.
	// crypto.Signer.Sign can't be cancelled once it's running, so the only control MSAL has is not
	// starting one for an acquisition that's already been cancelled.
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("unable to sign JWT token: %w", err)
	}

	assertion, err := build(signingMethod, thumbprintKey)
	if err == nil {
		return assertion, nil
	}
	if exportableRSA || isADFSorDSTS || !isSignerFailure(err) {
		// an exportable key is an *rsa.PrivateKey, and Go's software RSA always supports PSS, so
		// there's nothing to fall back from. ADFS and dSTS already signed with RS256. And a failure
		// that isn't the signer's -- assembling or marshaling the assertion -- fails the same way
		// under any algorithm, so retrying it would only bury the real error behind a second one.
		return "", fmt.Errorf("unable to sign JWT token: %w", err)
	}

	// The signer couldn't produce the PS256 signature. Some key providers (CNG, KeyGuard, HSMs,
	// smart cards) can't do RSA-PSS at all, so try once more with PKCS #1 v1.5, as MSAL .NET does.
	//
	// This retry downgrades the algorithm after a failure MSAL can't fully attribute, which is a
	// deliberate, security-reviewed trade-off rather than an oversight. crypto.Signer defines no
	// sentinel for "this algorithm is unsupported", and provider errors aren't portably classifiable
	// -- a CNG NTE_NOT_SUPPORTED, a PKCS #11 CKR_MECHANISM_INVALID and a vendor-specific HSM status
	// have nothing in common to match on -- so a provider that failed PS256 for some other reason
	// (permission denied, key deleted, device unavailable, cancellation) is retried as well. What
	// bounds that:
	//   - only signer-backed credentials reach this line. An exportable *rsa.PrivateKey is rejected
	//     above, so no caller silently loses PSS on a key that supports it.
	//   - RS256 isn't a downgrade to something weak or deprecated. It's an algorithm the service
	//     accepts for client assertions, and it's what MSAL already sends to ADFS and dSTS.
	//   - the retry is one further call into a key store the caller owns. For a store on the local
	//     machine, inducing a signer failure already requires control of it. That bound is weaker for
	//     a signer that calls out to a remote service, as the comment above contemplates: whoever can
	//     fail the first call can force RS256 without any access to the key. What that buys is
	//     limited -- the same key signs the same claims with an algorithm the service already accepts
	//     -- but a successful retry is silent, so it's documented on the exported constructors.
	//   - a real failure still fails: if RS256 fails too, both errors are reported below.
	//
	// Memoizing the outcome was considered and rejected. toInternal() runs once, in New(), so this
	// Credential outlives every request its Client makes; pinning RS256 after one transient failure
	// would make the downgrade permanent for the life of the process, which is a strictly worse
	// version of the risk above.
	if ctxErr := ctx.Err(); ctxErr != nil {
		// as above, don't start a signing operation the caller has already given up on
		return "", fmt.Errorf("unable to sign JWT token: signing with PS256 failed (%v) and the context ended before retrying with RS256: %w", err, ctxErr)
	}
	fallbackMethod, fallbackErr := newSignerMethod(jwt.SigningMethodRS256)
	if fallbackErr == nil {
		assertion, fallbackErr = build(fallbackMethod, "x5t")
		if fallbackErr == nil {
			return assertion, nil
		}
	}

	return "", fmt.Errorf("unable to sign JWT token: signing with PS256 failed (%v) and so did falling back to RS256: %w", err, fallbackErr)
}

// thumbprint runs the asn1.Der bytes through sha1 for use in the x5t parameter of JWT.
// https://tools.ietf.org/html/rfc7517#section-4.8
func thumbprint(cert *x509.Certificate, alg string) []byte {
	switch alg {
	case jwt.SigningMethodRS256.Name: // identity providers like ADFS don't support SHA256 assertions, so need to support this
		hash := sha1.Sum(cert.Raw) /* #nosec */
		return hash[:]
	default:
		hash := sha256.Sum256(cert.Raw)
		return hash[:]
	}
}

// Client represents the REST calls to get tokens from token generator backends.
type Client struct {
	// Comm provides the HTTP transport client.
	Comm urlFormCaller

	testing bool
}

// FromUsernamePassword uses a username and password to get an access token.
func (c Client) FromUsernamePassword(ctx context.Context, authParameters authority.AuthParams) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.Password)
	qv.Set(username, authParameters.Username)
	qv.Set(password, authParameters.Password)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

// AuthCodeRequest stores the values required to request a token from the authority using an authorization code
type AuthCodeRequest struct {
	AuthParams    authority.AuthParams
	Code          string
	CodeChallenge string
	Credential    *Credential
	AppType       AppType
}

// NewCodeChallengeRequest returns an AuthCodeRequest that uses a code challenge..
func NewCodeChallengeRequest(params authority.AuthParams, appType AppType, cc *Credential, code, challenge string) (AuthCodeRequest, error) {
	if appType == ATUnknown {
		return AuthCodeRequest{}, fmt.Errorf("bug: NewCodeChallengeRequest() called with AppType == ATUnknown")
	}
	return AuthCodeRequest{
		AuthParams:    params,
		AppType:       appType,
		Code:          code,
		CodeChallenge: challenge,
		Credential:    cc,
	}, nil
}

// FromAuthCode uses an authorization code to retrieve an access token.
func (c Client) FromAuthCode(ctx context.Context, req AuthCodeRequest) (TokenResponse, error) {
	var qv url.Values

	switch req.AppType {
	case ATUnknown:
		return TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with AppType == ATUnknown")
	case ATConfidential:
		var err error
		if req.Credential == nil {
			return TokenResponse{}, fmt.Errorf("AuthCodeRequest had nil Credential for Confidential app")
		}
		qv, err = prepURLVals(ctx, req.Credential, req.AuthParams)
		if err != nil {
			return TokenResponse{}, err
		}
	case ATPublic:
		qv = url.Values{}
	default:
		return TokenResponse{}, fmt.Errorf("bug: Token.AuthCode() received request with AppType == %v, which we do not recongnize", req.AppType)
	}

	qv.Set(grantType, grant.AuthCode)
	qv.Set("code", req.Code)
	qv.Set("code_verifier", req.CodeChallenge)
	qv.Set("redirect_uri", req.AuthParams.Redirecturi)
	qv.Set(clientID, req.AuthParams.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, req.AuthParams)
	if err := addClaims(qv, req.AuthParams); err != nil {
		return TokenResponse{}, err
	}

	return c.doTokenResp(ctx, req.AuthParams, qv)
}

// FromRefreshToken uses a refresh token (for refreshing credentials) to get a new access token.
func (c Client) FromRefreshToken(ctx context.Context, appType AppType, authParams authority.AuthParams, cc *Credential, refreshToken string) (TokenResponse, error) {
	qv := url.Values{}
	if appType == ATConfidential {
		var err error
		qv, err = prepURLVals(ctx, cc, authParams)
		if err != nil {
			return TokenResponse{}, err
		}
	}
	if err := addClaims(qv, authParams); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.RefreshToken)
	qv.Set(clientID, authParams.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("refresh_token", refreshToken)
	addScopeQueryParam(qv, authParams)

	return c.doTokenResp(ctx, authParams, qv)
}

// FromClientSecret uses a client's secret (aka password) to get a new token.
func (c Client) FromClientSecret(ctx context.Context, authParameters authority.AuthParams, clientSecret string) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set("client_secret", clientSecret)
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	// Add extra body parameters if provided
	if err := addExtraBodyParameters(ctx, qv, authParameters); err != nil {
		return TokenResponse{}, err
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) FromAssertion(ctx context.Context, authParameters authority.AuthParams, assertion string) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.ClientCredential)
	// A certificate-bound client assertion is signalled with the jwt-pop assertion type and the
	// binding certificate is presented on the TLS handshake (see doTokenResp).
	//
	// The trigger is the assertion being bound to a certificate the application handed over together
	// with it (via the signed-assertion callback), not merely the presence of a binding certificate
	// on the request. MSAL .NET draws the same line across its two client credentials:
	//
	//   - ClientAssertionDelegateCredential.cs:63-66 (the FIC/callback credential, equivalent to
	//     confidential.NewCredFromSignedAssertionCallback) selects JwtPop when the transport is mTLS
	//     *or* the ClientSignedAssertion carried a token-binding certificate, and JwtBearer otherwise.
	//   - CertificateAndClaimsClientCredential.cs:117 (the plain certificate credential, equivalent
	//     to NewCredFromCert/NewCredFromTLSCertificate) sets JwtBearer *unconditionally*, and still
	//     returns CredentialMaterial carrying the certificate: it hands a binding certificate to the
	//     transport while keeping the assertion jwt-bearer.
	//
	// FromAssertion is shared by both credential kinds, so keying this on MtlsBindingCert != nil would
	// wrongly catch the second one: a Bearer-over-mTLS request from a certificate credential sets a
	// binding certificate without requesting an mtls_pop token, and must stay jwt-bearer. That is why
	// this keys on AssertionBoundToCallbackCert, which only the callback path sets.
	assertionType := grant.ClientAssertion
	if authParameters.IsMtlsPoP || authParameters.AssertionBoundToCallbackCert {
		assertionType = grant.ClientAssertionPoP
	}
	qv.Set("client_assertion_type", assertionType)
	qv.Set("client_assertion", assertion)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	// Add extra body parameters if provided
	if err := addExtraBodyParameters(ctx, qv, authParameters); err != nil {
		return TokenResponse{}, err
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

// FromClientCertificate requests an mTLS proof-of-possession token authenticated solely by the
// client certificate presented on the mutual-TLS handshake. Unlike the assertion path it sends no
// client_assertion and no req_cnf: the TLS client certificate authenticates the client and binds the
// resulting token (token_type=mtls_pop). authParameters.MtlsBindingCert must be set.
func (c Client) FromClientCertificate(ctx context.Context, authParameters authority.AuthParams) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.ClientCredential)
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	// Add extra body parameters if provided
	if err := addExtraBodyParameters(ctx, qv, authParameters); err != nil {
		return TokenResponse{}, err
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) FromUserAssertionClientSecret(ctx context.Context, authParameters authority.AuthParams, userAssertion string, clientSecret string) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.JWT)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set("client_secret", clientSecret)
	qv.Set("assertion", userAssertion)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("requested_token_use", "on_behalf_of")
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) FromUserAssertionClientCertificate(ctx context.Context, authParameters authority.AuthParams, userAssertion string, assertion string) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.JWT)
	qv.Set("client_assertion_type", grant.ClientAssertion)
	qv.Set("client_assertion", assertion)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set("assertion", userAssertion)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("requested_token_use", "on_behalf_of")
	addScopeQueryParam(qv, authParameters)

	// Add extra body parameters if provided
	if err := addExtraBodyParameters(ctx, qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	return c.doTokenResp(ctx, authParameters, qv)
}

// FromUserFederatedIdentityCredential acquires a user-scoped token using the user_fic grant type.
// This exchanges a federated identity credential for a user token.
func (c Client) FromUserFederatedIdentityCredential(ctx context.Context, authParameters authority.AuthParams, cred *Credential) (TokenResponse, error) {
	if cred.Secret == "" && cred.Cert == nil && cred.AssertionCallback == nil {
		return TokenResponse{}, fmt.Errorf("user_fic requires a client secret or assertion credential; token provider credentials are not supported")
	}
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.UserFIC)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set("user_federated_identity_credential", authParameters.UserFederatedIdentityCredential)
	qv.Set(clientInfo, clientInfoVal)

	// Set user identifier: either user_id (OID) or username (UPN)
	if authParameters.UserObjectID != "" {
		qv.Set("user_id", authParameters.UserObjectID)
	} else if authParameters.Username != "" {
		qv.Set("username", authParameters.Username)
	}

	addScopeQueryParam(qv, authParameters)
	if err := addExtraBodyParameters(ctx, qv, authParameters); err != nil {
		return TokenResponse{}, err
	}

	credParams, err := prepURLVals(ctx, cred, authParameters)
	if err != nil {
		return TokenResponse{}, err
	}
	for k, vs := range credParams {
		for _, v := range vs {
			qv.Set(k, v)
		}
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) DeviceCodeResult(ctx context.Context, authParameters authority.AuthParams) (DeviceCodeResult, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return DeviceCodeResult{}, err
	}
	qv.Set(clientID, authParameters.ClientID)
	addScopeQueryParam(qv, authParameters)

	endpoint := strings.Replace(authParameters.Endpoints.TokenEndpoint, "token", "devicecode", -1)

	resp := DeviceCodeResponse{}
	err := c.Comm.URLFormCall(ctx, endpoint, qv, &resp)
	if err != nil {
		return DeviceCodeResult{}, err
	}

	return resp.Convert(authParameters.ClientID, authParameters.Scopes), nil
}

func (c Client) FromDeviceCodeResult(ctx context.Context, authParameters authority.AuthParams, deviceCodeResult DeviceCodeResult) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(grantType, grant.DeviceCode)
	qv.Set(deviceCode, deviceCodeResult.DeviceCode)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	addScopeQueryParam(qv, authParameters)

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) FromSamlGrant(ctx context.Context, authParameters authority.AuthParams, samlGrant wstrust.SamlTokenInfo) (TokenResponse, error) {
	qv := url.Values{}
	if err := addClaims(qv, authParameters); err != nil {
		return TokenResponse{}, err
	}
	qv.Set(username, authParameters.Username)
	qv.Set(password, authParameters.Password)
	qv.Set(clientID, authParameters.ClientID)
	qv.Set(clientInfo, clientInfoVal)
	qv.Set("assertion", base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString([]byte(samlGrant.Assertion)))
	addScopeQueryParam(qv, authParameters)

	switch samlGrant.AssertionType {
	case grant.SAMLV1:
		qv.Set(grantType, grant.SAMLV1)
	case grant.SAMLV2:
		qv.Set(grantType, grant.SAMLV2)
	default:
		return TokenResponse{}, fmt.Errorf("GetAccessTokenFromSamlGrant returned unknown SAML assertion type: %q", samlGrant.AssertionType)
	}

	return c.doTokenResp(ctx, authParameters, qv)
}

func (c Client) doTokenResp(ctx context.Context, authParams authority.AuthParams, qv url.Values) (TokenResponse, error) {
	resp := TokenResponse{}
	if authParams.AuthnScheme != nil {
		trParams := authParams.AuthnScheme.TokenRequestParams()
		for k, v := range trParams {
			qv.Set(k, v)
		}
	}
	endpoint := authParams.Endpoints.TokenEndpoint
	var err error
	if authParams.IsMtlsPoP || authParams.MtlsTransport {
		// mTLS transport: rewrite login.* -> mtlsauth.* and present the binding certificate on the TLS
		// handshake. This covers both mTLS PoP (token_type=mtls_pop) and Bearer-over-mTLS (plain Bearer
		// token). The endpoint derivation also enforces the mTLS guardrails (tenanted authority,
		// supported cloud, login.* host).
		endpoint, err = authParams.MtlsTokenEndpoint()
		if err != nil {
			return resp, err
		}
		err = c.Comm.URLFormCallWithCertificate(ctx, endpoint, qv, &resp, authParams.MtlsBindingCert)
	} else {
		err = c.Comm.URLFormCall(ctx, endpoint, qv, &resp)
	}
	if err != nil {
		return resp, err
	}
	resp.ComputeScope(authParams)
	if c.testing {
		return resp, nil
	}
	if err := resp.Validate(); err != nil {
		return resp, err
	}
	// mTLS PoP is a security primitive: when the caller requests a certificate-bound token the
	// identity provider must honor it. Fail closed on a downgrade (e.g. token_type=Bearer) rather
	// than returning a token that only looks bound. Mirrors MSAL .NET's TokenClient token_type
	// check (error code "token_type_mismatch").
	if authParams.IsMtlsPoP && !strings.EqualFold(resp.TokenType, authority.AccessTokenTypeMtlsPoP) {
		return resp, msalerrors.MtlsPoPTokenTypeMismatchError{
			Expected: authority.AccessTokenTypeMtlsPoP,
			Actual:   resp.TokenType,
		}
	}
	return resp, nil
}

// prepURLVals returns an url.Values that sets various key/values if we are doing secrets
// or JWT assertions.
func prepURLVals(ctx context.Context, cc *Credential, authParams authority.AuthParams) (url.Values, error) {
	params := url.Values{}
	if cc.Secret != "" {
		params.Set("client_secret", cc.Secret)
		return params, nil
	}

	jwt, err := cc.JWT(ctx, authParams)
	if err != nil {
		return nil, err
	}
	params.Set("client_assertion", jwt)
	params.Set("client_assertion_type", grant.ClientAssertion)
	return params, nil
}

// openid required to get an id token
// offline_access required to get a refresh token
// profile required to get the client_info field back
var detectDefaultScopes = map[string]bool{
	"openid":         true,
	"offline_access": true,
	"profile":        true,
}

var defaultScopes = []string{"openid", "offline_access", "profile"}

func AppendDefaultScopes(authParameters authority.AuthParams) []string {
	scopes := make([]string, 0, len(authParameters.Scopes)+len(defaultScopes))
	for _, scope := range authParameters.Scopes {
		s := strings.TrimSpace(scope)
		if s == "" {
			continue
		}
		if detectDefaultScopes[scope] {
			continue
		}
		scopes = append(scopes, scope)
	}
	scopes = append(scopes, defaultScopes...)
	return scopes
}

// addClaims adds client capabilities and claims from AuthParams to the given url.Values
func addClaims(v url.Values, ap authority.AuthParams) error {
	claims, err := ap.MergeCapabilitiesAndClaims()
	if err == nil && claims != "" {
		v.Set("claims", claims)
	}
	return err
}

func addScopeQueryParam(queryParams url.Values, authParameters authority.AuthParams) {
	scopes := AppendDefaultScopes(authParameters)
	queryParams.Set("scope", strings.Join(scopes, " "))
}

// reservedBodyParameters are token-request body parameters that MSAL owns. addExtraBodyParameters
// uses url.Values.Set, which overwrites, and runs last in every request builder, so an extra body
// parameter under one of these keys would silently replace a value MSAL computed - the client
// assertion, the grant type, the client identity, or the requested token type - and change what is
// actually being requested or how the client is authenticated.
//
// Nothing in this module can currently populate these keys: the only writers of ExtraBodyParameters
// are WithFMIPath and WithAttribute, and both hardcode their key. This is a guard placed ahead of
// any future caller-supplied extra-parameters API rather than a fix for a reachable hole. It lives
// inside addExtraBodyParameters, not at one call site, so it covers all five request builders and
// any that are added later.
var reservedBodyParameters = map[string]struct{}{
	"client_assertion":      {},
	"client_assertion_type": {},
	"req_cnf":               {},
	grantType:               {},
	clientID:                {},
	"token_type":            {},
}

// addExtraBodyParameters evaluates and adds extra body parameters to the request. It reports an
// error rather than letting an extra parameter overwrite a value MSAL owns; see
// reservedBodyParameters.
func addExtraBodyParameters(ctx context.Context, v url.Values, ap authority.AuthParams) error {
	for key, value := range ap.ExtraBodyParameters {
		if value == "" {
			continue
		}
		if _, reserved := reservedBodyParameters[key]; reserved {
			return fmt.Errorf("%q is reserved by MSAL and cannot be set as an extra body parameter", key)
		}
		v.Set(key, value)
	}
	return nil
}

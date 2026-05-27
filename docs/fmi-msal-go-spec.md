# Federated Managed Identity (FMI) Design Specification for MSAL Go

**Version:** 1.0
**Status:** Draft

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Background and Problem Statement](#background-and-problem-statement)
3. [Requirements](#requirements)
4. [Architecture Overview](#architecture-overview)
5. [Cache Extensibility Design](#cache-extensibility-design)
6. [FMI Core Features](#fmi-core-features)
7. [External Attributes and Federated Claims](#external-attributes-and-federated-claims)
8. [API Design](#api-design)
9. [Implementation Phases](#implementation-phases)
10. [Testing Strategy](#testing-strategy)

## Executive Summary

This specification defines the design for implementing Federated Managed Identity (FMI) support in the Microsoft Authentication Library (MSAL) for Go. FMI enables directory-less identities for high-cardinality scenarios while supporting external attributes and federated claims. The implementation will extend MSAL Go with cache extensibility, FMI credential management, and attribute token support.

## Background and Problem Statement

### Current Limitations

1. **Directory Scale Limits**: Traditional directory-based identities cannot support high-cardinality scenarios (millions of entities)
2. **Attribute Storage**: External attributes must be federated from various authorities outside the directory
3. **Cache Limitations**: Current cache implementation lacks extensibility for FMI-specific requirements
4. **Missing FMI Support**: MSAL Go lacks support for FMI flows defined in the FMI Protocol Specification v1.0

### Target Scenarios

- **Kubernetes Pods**: High-cardinality managed resources in K8s clusters
- **Service Fabric Services**: Distributed microservices requiring identity
- **Azure Arc Resources**: Edge compute resources with federated identity needs
- **Data Services**: SQL databases and other data resources with external attributes

## Requirements

### Functional Requirements

1. **Cache Extensibility**
   - Pluggable cache serialization/deserialization
   - Custom cache key generation for FMI paths
   - Support for external cache stores
   - Cache partitioning by FMI path hash

2. **FMI Core Flows**
   - RMA credential acquisition (Flow 1)
   - RMA token acquisition (Flow 2)
   - FMI-to-FMI credential acquisition (Flow 3)
   - FMI token acquisition from credentials (Flow 5)

3. **External Attributes**
   - Attribute token validation and processing
   - Federated claims integration
   - Multi-authority attribute support
   - Attribute namespacing and isolation

4. **Authentication Methods**
   - Certificate-based authentication with X5C
   - FMI credential-based authentication
   - Client assertion support for FMI flows

### Non-Functional Requirements

1. **Performance**: Token acquisition within 100ms for cached scenarios
2. **Security**: PKI-based validation, secure credential storage
3. **Reliability**: 99.9% success rate for valid requests
4. **Scalability**: Support for 1M+ FMI identities per application

## Architecture Overview

```
MSAL Go FMI Architecture

┌─────────────────────────────────────────────────┐
│              Application Layer                  │
│ RMA Services │ Sub-RMAs │ Resource Applications │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│              Public API Layer                  │
│                                                │
│ confidential.New() + WithFMIPath() +           │
│            WithAttributes()                    │
│ .AcquireTokenForClient()                       │
│                                                │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│           Core FMI Processing                   │
│                                                 │
│ FMI Path       │ FMI Credential │ Attribute     │
│ Processor      │ Manager        │ Manager       │
│                                                 │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│           Extended Storage Layer                │
│                                                 │
│         AccessToken struct + Key()              │
│         • FMIPath, FMIPathHash fields           │
│         • Extended key generation               │
│                                                 │
│ InMemoryContract ◄─────────► External Cache    │
│                                                 │
└─────────────────────┬───────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────┐
│           Protocol & Network Layer              │
│                                                 │
│ OAuth2 Client │ JWT Processor │ HTTP Client     │
│                                                 │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
              ┌─────────────────┐
              │  ESTS/Entra     │
              │ Token Endpoint  │
              └─────────────────┘

FMI Flows:
  Flow 1: RMA gets an FMI cred, for a leaf entity or for a sub-RMA
  Flow 2: RMA gets an FMI token for a leaf entity
  Flow 3: sub-RMA, who has an FMI credential, gets an FMI credential for a child sub-RMA
  Flow 4: FMI Cred → FMI Token

Cache Key: {fields}[-{FMIPathHash}]
```
The existing MSAL Go cache uses `AccessToken` structs in `apps/internal/base/storage/items.go` with a `Key()` method for cache key generation. For FMI support, we extend the `AccessToken` struct to include FMI path information and modify its `Key()` method.

```go
// Extension to existing AccessToken struct in apps/internal/base/storage/items.go
type AccessToken struct {
    HomeAccountID     string            `json:"home_account_id,omitempty"`
    Environment       string            `json:"environment,omitempty"`
    Realm             string            `json:"realm,omitempty"`
    CredentialType    string            `json:"credential_type,omitempty"`
    ClientID          string            `json:"client_id,omitempty"`
    Secret            string            `json:"secret,omitempty"`
    Scopes            string            `json:"target,omitempty"`
    RefreshOn         internalTime.Unix `json:"refresh_on,omitempty"`
    ExpiresOn         internalTime.Unix `json:"expires_on,omitempty"`
    ExtendedExpiresOn internalTime.Unix `json:"extended_expires_on,omitempty"`
    CachedAt          internalTime.Unix `json:"cached_at,omitempty"`
    UserAssertionHash string            `json:"user_assertion_hash,omitempty"`
    TokenType         string            `json:"token_type,omitempty"`
    AuthnSchemeKeyID  string            `json:"keyid,omitempty"`

    // NEW: FMIPath and Attributes fields
    FMIPath           string            `json:"fmi_path,omitempty"`           // Original FMI path
    Attributes       string             `json:"attributes,omitempty"`      	  // Attributes
    AdditionalFields map[string]interface{}
}

// Extended Key() method for AccessToken to include FMI path hash
func (a AccessToken) Key() string {
    ks := []string{a.HomeAccountID, a.Environment, a.CredentialType, a.ClientID, a.Realm, a.Scopes}
    key := strings.Join(ks, shared.CacheKeySeparator)

    // Add token type to key for new access tokens types (existing logic)
    if !strings.EqualFold(a.TokenType, authority.AccessTokenTypeBearer) {
        key = strings.Join([]string{key, a.TokenType}, shared.CacheKeySeparator)
    }

    // NEW: Add FMI path hash to key for FMI tokens
    key = strings.Join([]string{key, generateFMIPathHash}, shared.CacheKeySeparator)
    return strings.ToLower(key)
}

// Utility function to generate FMI path hash (SHA256, base64url encoded)
func generateFMIPathHash(fmiPath string, attributes string) string {
    if fmiPath == "" || attributes == "" {
        return ""
    }
    hash := sha256.Sum256([]byte("attributes" + attributes + "fmi_path" + fmiPath))
    return base64.RawURLEncoding.EncodeToString(hash[:])
}

```

### Cache Extension Strategy

1. **Extend Existing Structs**: Add FMI fields to existing `AccessToken` struct instead of creating new types
2. **Backward Compatibility**: Existing cache keys remain unchanged when FMI path is empty
3. **Key Method Extension**: Modify existing `Key()` method to conditionally include FMI path hash
4. **Constructor Pattern**: Follow existing `NewAccessToken` pattern with `NewFMIAccessToken`
5. **Cache Partitioning**: Different FMI paths get separate cache entries automatically through key generation

### Cache Key Format (Using existing Key() method pattern)

The existing `AccessToken.Key()` method generates keys like:
- **Current Format**: `{HomeAccountID}-{Environment}-{CredentialType}-{ClientID}-{Realm}-{Scopes}[-{TokenType}]`
- **FMI Extension**: `{HomeAccountID}-{Environment}-{CredentialType}-{ClientID}-{Realm}-{Scopes}[-{TokenType}][-{AttributeFMIPathHash}]`

Where:
- `HomeAccountID`: Account identifier (empty for app-only tokens)
- `Environment`: Authority host (e.g., "login.microsoftonline.com")
- `CredentialType`: "AccessToken"
- `ClientID`: Application client ID
- `Realm`: Tenant ID
- `Scopes`: Target scopes
- `TokenType`: Bearer, PoP, etc. (optional)
- `FMIPathHash`: SHA256 of FMI path, base64url encoded (NEW, optional)

## FMI Core Features

### FMI Path Management

```go
type FMIPath struct {
    Path     string    // e.g., "SomeFmiPath/FmiCredentialPath"
    Hash     string    // SHA256 hash of the path
    Segments []string  // Split path components
}

func (f *FMIPath) Validate() error
func (f *FMIPath) GenerateHash() string
func NewFMIPath(path string) (*FMIPath, error)
```

### Credential Types

1. **Certificate-based Credentials**
   - X.509 certificate with private key
   - Support for sendX5C parameter
   - SNI (Subject Name and Issuer) authentication

2. **FMI Credentials**
   - JWT tokens issued by RMAs
   - Used for sub-RMA scenarios
   - Support for credential chains

3. **Client Assertions**
   - Custom JWT assertions for FMI flows
   - Support for dynamic assertion generation

### Authentication Flows

#### Flow 1: RMA Credential Acquisition
```go
cred, err := confidential.NewCredFromCert(cert, true) // sendX5C enabled
if err != nil {
    // handle error
}

client, err := confidential.New(authority, clientID, cred,
    confidential.WithAzureRegion(region))
if err != nil {
    // handle error
}

result, err := client.AcquireTokenForClient(ctx, scopes,
    confidential.WithFMIPath("SomeFmiPath/FmiCredentialPath"))
```

#### Flow 2: RMA Token Acquisition
```go
result, err := client.AcquireTokenForClient(ctx, scopes,
    confidential.WithFMIPath(fmiPath),
    confidential.WithExtraQueryParameters(params))
```

#### Flow 3 & 5: FMI-to-FMI Flows
```go
cred, err := confidential.NewCredFromAssertion(assertionProvider)
if err != nil {
    // handle error
}

fmiClient, err := confidential.New(authority, "urn:microsoft:identity:fmi", cred,
    confidential.WithAzureRegion(region))
if err != nil {
    // handle error
}

result, err := fmiClient.AcquireTokenForClient(ctx, scopes,
    confidential.WithFMIPath(childPath))
```

## External Attributes and Federated Claims

### Attribute Token Structure

```go
type AttributeToken struct {
    Header AttributeTokenHeader `json:"header"`
    Claims AttributeTokenClaims `json:"claims"`

    // Validation state
    IsValidated bool
    Issuer      string
    Subject     string
}

type AttributeTokenClaims struct {
    Audience                string                 `json:"aud"`
    Issuer                  string                 `json:"iss"`
    JTI                     string                 `json:"jti"`
    Version                 string                 `json:"ver"`
    ExpirationTime          int64                  `json:"exp"`
    NotBefore              int64                  `json:"nbf"`
    Subject                string                 `json:"sub"`
    IdentityType           string                 `json:"idtyp"`
    AuthContextBinding     []string               `json:"xms_acb"`
    Attributes             map[string]string      `json:"xms_attr"`
}
```

### Attribute Manager

```go
type AttributeManager interface {
    // Token operations
    ValidateAttributeToken(ctx context.Context, token string) (*AttributeToken, error)
    FederateAttributes(ctx context.Context, tokens []string) (map[string]map[string]string, error)

    // Authority management
    RegisterAttributeAuthority(authorityID string, publicKey interface{}) error
    GetAttributesByAuthority(claims map[string]map[string]string, authorityID string) map[string]string

    // Encryption support
    EncryptAttributeToken(token *AttributeToken, recipientKey interface{}) (string, error)
    DecryptAttributeToken(encryptedToken string, privateKey interface{}) (*AttributeToken, error)
}
```

### Federated Claims Integration

1. **Token Request Enhancement**: Add `attribute_tokens` parameter to OAuth requests
2. **Claim Processing**: Validate and namespace attributes by authority
3. **Token Enrichment**: Embed federated claims in access tokens
4. **Authority Validation**: Verify attribute authority signatures

## API Design

### Core Client Interface

```go
// FMI support is integrated into existing Client interface through options
type Client interface {
    // Standard token acquisition with FMI options
    AcquireTokenSilent(ctx context.Context, scopes []string, opts ...AcquireTokenSilentOption) (AuthResult, error)
    AcquireTokenForClient(ctx context.Context, scopes []string, opts ...AcquireTokenForClientOption) (AuthResult, error)

    // Cache management with FMI support
    Accounts(ctx context.Context) []Account
    RemoveAccount(ctx context.Context, account Account) error
}

// New option types for FMI support
type AcquireTokenForClientOption func(*AcquireTokenForClientOptions)
type AcquireTokenSilentOption func(*AcquireTokenSilentOptions)

// FMI-specific options
func WithFMIPath(path string) AcquireTokenForClientOption
func WithAttributes(attributes map[string]string) AcquireTokenForClientOption
func WithAttributeTokens(tokens []string) AcquireTokenForClientOption
func WithFMISilentAccount(account Account) AcquireTokenSilentOption
```

### Client Configuration Extensions

```go
// Existing confidential.New function extended with FMI options
func New(authority, clientID string, cred Credential, options ...Option) (Client, error)

// FMI-specific configuration options
type Option func(*Options)

func WithFMIPathProvider(provider FMIPathProvider) Option
func WithAttributeManager(manager AttributeManager) Option
func WithTrustedAttributeAuthorities(authorities []string) Option
// Note: Cache key generation is extended internally, no new WithCacheKeyGenerator needed
```

### Options and Configuration

```go
// AcquireTokenForClient options
type AcquireTokenForClientOptions struct {
    FMIPath         string
    Attributes      map[string]string
    AttributeTokens []string
    // ... existing options
}

// AcquireTokenSilent options
type AcquireTokenSilentOptions struct {
    Account Account // Can be FMI account
    // ... existing options
}

// Option functions follow existing MSAL Go patterns
func WithFMIPath(path string) AcquireTokenForClientOption {
    return func(o *AcquireTokenForClientOptions) {
        o.FMIPath = path
    }
}

func WithAttributes(attributes map[string]string) AcquireTokenForClientOption {
    return func(o *AcquireTokenForClientOptions) {
        o.Attributes = attributes
    }
}

func WithAttributeTokens(tokens []string) AcquireTokenForClientOption {
    return func(o *AcquireTokenForClientOptions) {
        o.AttributeTokens = tokens
    }
}
```

## Implementation Phases

### Phase 1: Cache Extensibility (Weeks 1-3)
- [ ] Extend existing `AccessToken` struct with FMI fields (`FMIPath`, `FMIPathHash`)
- [ ] Modify existing `Key()` method to conditionally include FMI path hash
- [ ] Add `NewFMIAccessToken` constructor following existing patterns
- [ ] FMI path hash generation utility (SHA256, base64url)
- [ ] Backward compatibility testing with existing cache keys
- [ ] Unit tests for extended `Key()` method with FMI paths

### Phase 2: FMI Core Features (Weeks 4-7)
- [ ] FMI path management and validation
- [ ] Certificate authentication with X5C
- [ ] FMI client builder and configuration
- [ ] Flow 1 & 2 implementation (RMA flows)
- [ ] Integration tests with ESTS test slice

### Phase 3: Advanced FMI Flows (Weeks 8-10)
- [ ] Client assertion providers
- [ ] Flow 3 & 5 implementation (FMI-to-FMI)
- [ ] FMI credential management
- [ ] Error handling and retry logic
- [ ] Performance optimization

### Phase 4: External Attributes (Weeks 11-14)
- [ ] Attribute token validation
- [ ] JWT processing with encryption support
- [ ] Attribute manager implementation
- [ ] Federated claims integration
- [ ] Multi-authority support

### Phase 5: Testing and Documentation (Weeks 15-16)
- [ ] Comprehensive integration tests
- [ ] Performance benchmarking
- [ ] Security review and penetration testing
- [ ] API documentation and samples
- [ ] Migration guide from standard MSAL

## Testing Strategy

### Unit Testing
- **Cache Layer**: All interface implementations, serialization
- **FMI Components**: Path validation, credential management
- **Attribute Processing**: Token validation, claim federation
- **JWT Handling**: Signing, verification, encryption

### Integration Testing
- **ESTS Integration**: All FMI flows against test slice
- **Cache Integration**: External cache stores
- **End-to-End Scenarios**: Complete authentication flows
- **Error Scenarios**: Network failures, invalid tokens

### Performance Testing
- **Cache Performance**: 10K+ operations per second
- **Token Acquisition**: Sub-100ms for cached scenarios
- **Memory Usage**: Efficient with large FMI path counts
- **Concurrent Access**: Thread safety under load

### Security Testing
- **Certificate Validation**: X.509 chain validation
- **JWT Security**: Signature verification, timing attacks
- **Attribute Security**: Authority validation, namespace isolation
- **Cache Security**: Secure serialization, no credential leakage

## Appendix A: Error Codes

| Error Code | Description | Mitigation |
|------------|-------------|------------|
| `FMI_INVALID_PATH` | FMI path format is invalid | Validate path format |
| `FMI_CREDENTIAL_EXPIRED` | FMI credential has expired | Refresh from RMA |
| `ATTRIBUTE_TOKEN_INVALID` | Attribute token validation failed | Check token format and signature |
| `CACHE_SERIALIZATION_ERROR` | Cache serialization/deserialization failed | Verify cache format |
| `AUTHORITY_NOT_TRUSTED` | Attribute authority not in trust list | Register authority |

## Appendix B: Configuration Examples

### Basic FMI Client
```go
cred, err := confidential.NewCredFromCert(cert, true)
if err != nil {
    // handle error
}

client, err := confidential.New(
    "https://login.microsoftonline.com/"+tenantID,
    clientID,
    cred,
    confidential.WithFMIPathProvider(staticFMIProvider))
```

### Advanced Cache Configuration
```go
cred, err := confidential.NewCredFromSecret(clientSecret)
if err != nil {
    // handle error
}

// Cache key generation for FMI is handled internally
// Existing cache options still work, FMI extends key generation automatically
client, err := confidential.New(authority, clientID, cred)
```

### Attribute-Enabled Client
```go
cred, err := confidential.NewCredFromCert(cert, true)
if err != nil {
    // handle error
}

client, err := confidential.New(authority, clientID, cred,
    confidential.WithAttributeManager(NewDefaultAttributeManager()),
    confidential.WithTrustedAttributeAuthorities(authorityList))
```

# W3C VC Data Integrity OpenID4VP Handler - Implementation Specification

**Status: Implemented** (January 2026)

This document provides detailed implementation specifications for integrating W3C Verifiable Credentials Data Integrity with OpenID4VP, ensuring feature parity with existing SD-JWT and mDoc handlers.

## Implementation Summary

The handler is implemented in `pkg/openid4vp/vc20_handler.go` with the `vc20` build tag.

**Supported Cryptosuites:**
- `ecdsa-rdfc-2019` - Standard ECDSA Data Integrity proofs
- `ecdsa-sd-2023` - ECDSA Selective Disclosure (BASE and DERIVED proofs)
- `eddsa-rdfc-2022` - EdDSA Data Integrity proofs

**Key Features:**
- Key resolution via pluggable `VC20KeyResolver` interface
- Trusted issuer validation
- CreateCredential for signing new credentials
- VerifyAndExtract for credential verification
- VP and VC parsing (base64url and plain JSON)

## Handler Interface Design

### Core Types

```go
// pkg/openid4vp/vc20_handler.go

package openid4vp

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "encoding/json"
    "fmt"
    "time"
    
    "vc/pkg/vc20/credential"
    "vc/pkg/vc20/crypto/ecdsa"
)

// VC20Format identifiers per OpenID4VC spec
const (
    FormatLdpVC     = "ldp_vc"      // VC Data Model 1.1 with Data Integrity
    FormatVC20JSON  = "vc+ld+json"  // VC Data Model 2.0 with Data Integrity
)

// VC20KeyResolver resolves verification method URIs to public keys
type VC20KeyResolver interface {
    // ResolveKey resolves a DID verification method to a public key
    // verificationMethod can be:
    //   - Full DID URL: "did:key:z6Mk...#key-1"
    //   - DID with fragment: "did:web:example.com#keys-1"
    //   - HTTP URL: "https://example.com/keys/1"
    ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
}

// VC20HandlerOption configures a VC20Handler
type VC20HandlerOption func(*VC20Handler)

// VC20Handler verifies W3C VC 2.0 Data Integrity credentials
type VC20Handler struct {
    keyResolver     VC20KeyResolver
    trustedIssuers  map[string]bool
    contextLoader   ld.DocumentLoader
    checkRevocation bool
    clock           func() time.Time
}

// NewVC20Handler creates a new handler with options
func NewVC20Handler(opts ...VC20HandlerOption) *VC20Handler {
    h := &VC20Handler{
        trustedIssuers: make(map[string]bool),
        clock:          time.Now,
    }
    for _, opt := range opts {
        opt(h)
    }
    return h
}

// WithKeyResolver sets the key resolver
func WithKeyResolver(kr VC20KeyResolver) VC20HandlerOption {
    return func(h *VC20Handler) {
        h.keyResolver = kr
    }
}

// WithTrustedIssuers sets allowed issuers
func WithTrustedIssuers(issuers []string) VC20HandlerOption {
    return func(h *VC20Handler) {
        for _, iss := range issuers {
            h.trustedIssuers[iss] = true
        }
    }
}

// WithRevocationCheck enables credential status checking
func WithRevocationCheck(check bool) VC20HandlerOption {
    return func(h *VC20Handler) {
        h.checkRevocation = check
    }
}

// WithContextLoader sets the JSON-LD context loader
func WithContextLoader(loader ld.DocumentLoader) VC20HandlerOption {
    return func(h *VC20Handler) {
        h.contextLoader = loader
    }
}
```

### Verification Result

```go
// VC20VerificationResult contains verified credential data
type VC20VerificationResult struct {
    // Credential metadata
    ID             string     `json:"id,omitempty"`
    Issuer         string     `json:"issuer"`
    Subject        string     `json:"subject,omitempty"`
    Types          []string   `json:"type"`
    IssuanceDate   time.Time  `json:"validFrom"`
    ExpirationDate *time.Time `json:"validUntil,omitempty"`
    
    // Credential content
    CredentialSubject map[string]any `json:"credentialSubject"`
    
    // Proof metadata
    ProofType         string    `json:"proofType"`         // "DataIntegrityProof"
    Cryptosuite       string    `json:"cryptosuite"`       // "ecdsa-rdfc-2019" or "ecdsa-sd-2023"
    VerificationMethod string   `json:"verificationMethod"`
    ProofPurpose      string    `json:"proofPurpose"`
    ProofCreated      time.Time `json:"proofCreated"`
    
    // Selective disclosure (for ecdsa-sd-2023)
    IsSelectiveDisclosure bool     `json:"isSelectiveDisclosure"`
    DisclosedPaths        []string `json:"disclosedPaths,omitempty"`
    MandatoryPaths        []string `json:"mandatoryPaths,omitempty"`
    
    // Status
    RevocationStatus *RevocationStatus `json:"revocationStatus,omitempty"`
    
    // Raw credential for downstream processing
    RawCredential json.RawMessage `json:"rawCredential"`
}

// RevocationStatus indicates credential revocation state
type RevocationStatus struct {
    Checked    bool   `json:"checked"`
    Revoked    bool   `json:"revoked"`
    StatusType string `json:"statusType"` // "BitstringStatusList", etc.
    StatusURL  string `json:"statusUrl,omitempty"`
}
```

### Main Verification Method

```go
// VerifyAndExtract verifies a W3C VC presentation and extracts claims
func (h *VC20Handler) VerifyAndExtract(ctx context.Context, vpToken string) (*VC20VerificationResult, error) {
    // 1. Decode VP token
    vpBytes, err := h.decodeVPToken(vpToken)
    if err != nil {
        return nil, &VerificationError{Code: ErrInvalidFormat, Err: err}
    }
    
    // 2. Parse VP structure
    var vp map[string]any
    if err := json.Unmarshal(vpBytes, &vp); err != nil {
        return nil, &VerificationError{Code: ErrInvalidFormat, Err: err}
    }
    
    // 3. Extract embedded credential(s)
    credentials, err := h.extractCredentials(vp)
    if err != nil {
        return nil, &VerificationError{Code: ErrInvalidStructure, Err: err}
    }
    
    if len(credentials) == 0 {
        return nil, &VerificationError{Code: ErrNoCredential, Err: fmt.Errorf("no credentials found")}
    }
    
    // 4. Verify first credential (extend for multi-credential support)
    credBytes := credentials[0]
    return h.verifyCredential(ctx, credBytes)
}

// verifyCredential verifies a single credential
func (h *VC20Handler) verifyCredential(ctx context.Context, credBytes []byte) (*VC20VerificationResult, error) {
    // Parse credential
    var cred map[string]any
    if err := json.Unmarshal(credBytes, &cred); err != nil {
        return nil, &VerificationError{Code: ErrInvalidFormat, Err: err}
    }
    
    // Extract and validate issuer
    issuer, err := h.extractIssuer(cred)
    if err != nil {
        return nil, err
    }
    
    // Check trusted issuers (if configured)
    if len(h.trustedIssuers) > 0 && !h.trustedIssuers[issuer] {
        return nil, &VerificationError{
            Code: ErrUntrustedIssuer,
            Err:  fmt.Errorf("issuer not trusted: %s", issuer),
        }
    }
    
    // Extract proof
    proof, err := h.extractProof(cred)
    if err != nil {
        return nil, err
    }
    
    // Determine cryptosuite and verify
    cryptosuite := proof["cryptosuite"].(string)
    
    switch cryptosuite {
    case "ecdsa-rdfc-2019":
        return h.verifyECDSA2019(ctx, credBytes, cred, proof)
    case "ecdsa-sd-2023":
        return h.verifyECDSASd2023(ctx, credBytes, cred, proof)
    default:
        return nil, &VerificationError{
            Code: ErrUnsupportedCryptosuite,
            Err:  fmt.Errorf("unsupported cryptosuite: %s", cryptosuite),
        }
    }
}
```

### Cryptosuite-Specific Verification

```go
// verifyECDSA2019 verifies ecdsa-rdfc-2019 proof
func (h *VC20Handler) verifyECDSA2019(
    ctx context.Context,
    credBytes []byte,
    cred map[string]any,
    proof map[string]any,
) (*VC20VerificationResult, error) {
    // Resolve verification method to public key
    vm := proof["verificationMethod"].(string)
    pubKey, err := h.keyResolver.ResolveKey(ctx, vm)
    if err != nil {
        return nil, &VerificationError{Code: ErrKeyResolution, Err: err}
    }
    
    ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, &VerificationError{
            Code: ErrInvalidKey,
            Err:  fmt.Errorf("expected ECDSA public key, got %T", pubKey),
        }
    }
    
    // Create RDF credential and verify
    rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
    if err != nil {
        return nil, &VerificationError{Code: ErrRDFProcessing, Err: err}
    }
    
    suite := ecdsa.NewSuite()
    if err := suite.Verify(rdfCred, ecdsaKey); err != nil {
        return nil, &VerificationError{Code: ErrSignatureInvalid, Err: err}
    }
    
    // Build result
    return h.buildResult(cred, proof, false, nil)
}

// verifyECDSASd2023 verifies ecdsa-sd-2023 proof (BASE or DERIVED)
func (h *VC20Handler) verifyECDSASd2023(
    ctx context.Context,
    credBytes []byte,
    cred map[string]any,
    proof map[string]any,
) (*VC20VerificationResult, error) {
    // Resolve verification method
    vm := proof["verificationMethod"].(string)
    pubKey, err := h.keyResolver.ResolveKey(ctx, vm)
    if err != nil {
        return nil, &VerificationError{Code: ErrKeyResolution, Err: err}
    }
    
    ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
    if !ok {
        return nil, &VerificationError{
            Code: ErrInvalidKey,
            Err:  fmt.Errorf("expected ECDSA public key, got %T", pubKey),
        }
    }
    
    // Create RDF credential
    rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
    if err != nil {
        return nil, &VerificationError{Code: ErrRDFProcessing, Err: err}
    }
    
    // Verify using SD suite
    sdSuite := ecdsa.NewSdSuite()
    disclosedPaths, err := sdSuite.Verify(rdfCred, ecdsaKey)
    if err != nil {
        return nil, &VerificationError{Code: ErrSignatureInvalid, Err: err}
    }
    
    // Build result with selective disclosure info
    return h.buildResult(cred, proof, true, disclosedPaths)
}
```

## Key Resolution Architecture

Key resolution and trust evaluation are unified through the **go-trust** service, with local resolution for self-contained DID methods.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     VC20Handler                                  │
│                         │                                        │
│                   VC20KeyResolver                                │
│                         │                                        │
│         ┌───────────────┴───────────────┐                       │
│         │                               │                        │
│   LocalDIDResolver              GoTrustKeyResolver               │
│   (did:key, did:jwk)            (all other methods)              │
│         │                               │                        │
│   Self-contained             ┌──────────┴──────────┐            │
│   key extraction             │    go-trust API     │            │
│                              │                      │            │
│                              │  - did:web           │            │
│                              │  - did:ebsi          │            │
│                              │  - ETSI TL           │            │
│                              │  - OpenID Fed        │            │
│                              │  - X.509/PKIX        │            │
│                              └──────────────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

### GoTrust Key Resolver

```go
// pkg/keyresolver/gotrust_resolver.go

package keyresolver

import (
    "context"
    "crypto"
    "strings"
    
    "github.com/sirosfoundation/go-trust/client"
)

// GoTrustKeyResolver resolves keys via go-trust with trust evaluation
type GoTrustKeyResolver struct {
    // GoTrustClient handles resolution and trust verification
    goTrustClient *client.Client
    
    // LocalResolver handles self-contained DIDs
    localResolver *LocalDIDResolver
    
    // TrustPolicies to apply during resolution
    trustPolicies []string
}

// NewGoTrustKeyResolver creates a resolver with go-trust backend
func NewGoTrustKeyResolver(goTrustURL string, policies []string) (*GoTrustKeyResolver, error) {
    gtClient, err := client.New(goTrustURL)
    if err != nil {
        return nil, err
    }
    
    return &GoTrustKeyResolver{
        goTrustClient: gtClient,
        localResolver: NewLocalDIDResolver(),
        trustPolicies: policies,
    }, nil
}

// ResolveKey resolves a verification method to a public key
func (r *GoTrustKeyResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
    // Self-contained DIDs are resolved locally (no trust evaluation needed)
    if r.isLocalDID(verificationMethod) {
        return r.localResolver.Resolve(ctx, verificationMethod)
    }
    
    // All other methods go through go-trust for resolution + trust evaluation
    return r.goTrustClient.ResolveAndVerify(ctx, verificationMethod, r.trustPolicies)
}

// isLocalDID returns true for self-contained DID methods
func (r *GoTrustKeyResolver) isLocalDID(vm string) bool {
    return strings.HasPrefix(vm, "did:key:") || strings.HasPrefix(vm, "did:jwk:")
}
```

### Local DID Resolver (Self-Contained Methods)

For DID methods where the key material is embedded in the identifier:

```go
// pkg/keyresolver/local_did_resolver.go

package keyresolver

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "encoding/base64"
    "fmt"
    "math/big"
    "strings"
    
    "github.com/multiformats/go-multibase"
)

// LocalDIDResolver handles self-contained DID methods
type LocalDIDResolver struct{}

// NewLocalDIDResolver creates a new local resolver
func NewLocalDIDResolver() *LocalDIDResolver {
    return &LocalDIDResolver{}
}

// Resolve extracts public key from self-contained DIDs
func (r *LocalDIDResolver) Resolve(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
    // Extract DID from verification method (may include fragment)
    did := strings.Split(verificationMethod, "#")[0]
    
    if strings.HasPrefix(did, "did:key:") {
        return r.resolveDidKey(did)
    }
    
    if strings.HasPrefix(did, "did:jwk:") {
        return r.resolveDidJwk(did)
    }
    
    return nil, fmt.Errorf("unsupported local DID method: %s", did)
}

// resolveDidKey extracts key from did:key (multicodec-encoded)
func (r *LocalDIDResolver) resolveDidKey(did string) (crypto.PublicKey, error) {
    // did:key:z6Mk... -> multibase-encoded public key
    parts := strings.Split(did, ":")
    if len(parts) < 3 {
        return nil, fmt.Errorf("invalid did:key format: %s", did)
    }
    
    multibaseKey := parts[2]
    
    // Decode multibase
    _, keyBytes, err := multibase.Decode(multibaseKey)
    if err != nil {
        return nil, fmt.Errorf("failed to decode multibase key: %w", err)
    }
    
    return r.parseMulticodecKey(keyBytes)
}

// resolveDidJwk extracts key from did:jwk (base64url-encoded JWK)
func (r *LocalDIDResolver) resolveDidJwk(did string) (crypto.PublicKey, error) {
    // did:jwk:<base64url-encoded-jwk>
    parts := strings.Split(did, ":")
    if len(parts) < 3 {
        return nil, fmt.Errorf("invalid did:jwk format: %s", did)
    }
    
    jwkBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
    if err != nil {
        return nil, fmt.Errorf("failed to decode JWK: %w", err)
    }
    
    var jwk JWK
    if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
        return nil, fmt.Errorf("failed to parse JWK: %w", err)
    }
    
    return r.parseJWKKey(&jwk)
}

// parseMulticodecKey parses a multicodec-prefixed key
func (r *LocalDIDResolver) parseMulticodecKey(keyBytes []byte) (crypto.PublicKey, error) {
    if len(keyBytes) < 2 {
        return nil, fmt.Errorf("key bytes too short")
    }
    
    // Check multicodec prefix
    // 0xed01 = Ed25519 public key
    // 0x1200 = P-256 public key (compressed)
    // 0x1201 = P-384 public key (compressed)
    
    if keyBytes[0] == 0xed && keyBytes[1] == 0x01 {
        // Ed25519: 32 bytes after prefix
        if len(keyBytes) < 34 {
            return nil, fmt.Errorf("Ed25519 key too short")
        }
        return ed25519.PublicKey(keyBytes[2:34]), nil
    }
    
    if keyBytes[0] == 0x80 && keyBytes[1] == 0x24 {
        // P-256 compressed: 33 bytes after prefix
        return r.decompressP256Key(keyBytes[2:])
    }
    
    return nil, fmt.Errorf("unsupported multicodec prefix: %x%x", keyBytes[0], keyBytes[1])
}
```

### Trust Evaluation via go-trust

The go-trust service handles all trust frameworks:

| Verification Method | go-trust Responsibility |
|---------------------|------------------------|
| `did:web:example.com#key-1` | Resolve DID document, verify domain binding |
| `did:ebsi:...` | Resolve via EBSI resolver, verify trust registry |
| `https://issuer.example.com/keys/1` | Resolve JWKS, evaluate ETSI TL or OpenID Fed |
| X.509 certificate | Validate chain against configured trust anchors |

The key insight is that **go-trust provides both resolution AND trust evaluation** - it doesn't just fetch keys, it verifies that the name-to-key binding is trusted according to configured policies.

### Configuration Example

```yaml
verifier:
  key_resolver:
    # go-trust service endpoint
    go_trust_url: "https://trust.example.com"
    
    # Trust policies (evaluated by go-trust)
    trust_policies:
      - "etsi_tl:eu-lotl"           # EU Trusted List
      - "openid_federation:eduGAIN" # eduGAIN federation
      - "pkix:internal_ca"          # Internal PKI
    
    # Local methods (always available, no go-trust needed)
    # These are inherently trustless - key IS the identifier
    local_did_methods:
      - "did:key"
      - "did:jwk"
```

## DCQL Format Support

```go
// pkg/openid4vp/dcql.go - additions

// MetaQuery extended for W3C VC format
type MetaQuery struct {
    // For SD-JWT format (dc+sd-jwt, vc+sd-jwt)
    VCTValues []string `json:"vct_values,omitempty" yaml:"vct_values"`
    
    // For W3C VC format (ldp_vc, vc+ld+json)
    TypeValues        []string `json:"type_values,omitempty" yaml:"type_values"`
    CryptosuiteValues []string `json:"cryptosuite_values,omitempty" yaml:"cryptosuite_values"`
    IssuerValues      []string `json:"issuer_values,omitempty" yaml:"issuer_values"`
}

// ClaimQuery for W3C VC uses JSON-LD path syntax
// Example paths for W3C VC:
//   ["credentialSubject", "givenName"]
//   ["credentialSubject", "address", "streetAddress"]
//
// Compare to SD-JWT:
//   ["given_name"]
//   ["address", "street_address"]
```

## Issuer Integration

```go
// internal/issuer/apiv1/handlers.go - additions

// CreateVC20Request for W3C VC issuance
type CreateVC20Request struct {
    DocumentData      []byte   `json:"document_data" validate:"required"`
    Scope             string   `json:"scope" validate:"required"`
    CredentialTypes   []string `json:"credential_types" validate:"required"`
    Contexts          []string `json:"contexts,omitempty"` // Additional @context URIs
    SubjectID         string   `json:"subject_id,omitempty"` // Credential subject ID (DID)
    Cryptosuite       string   `json:"cryptosuite"` // "ecdsa-rdfc-2019" or "ecdsa-sd-2023"
    MandatoryPointers []string `json:"mandatory_pointers,omitempty"` // For SD
}

// CreateVC20Reply contains the issued credential
type CreateVC20Reply struct {
    Credential json.RawMessage `json:"credential"`
}

// MakeVC20 creates a W3C VC Data Integrity credential
func (c *Client) MakeVC20(ctx context.Context, req *CreateVC20Request) (*CreateVC20Reply, error) {
    ctx, span := c.tracer.Start(ctx, "apiv1:MakeVC20")
    defer span.End()
    
    // Validate request
    if err := helpers.Check(ctx, c.cfg, req, c.log); err != nil {
        return nil, err
    }
    
    // Build credential structure
    cred := map[string]any{
        "@context": append([]string{
            "https://www.w3.org/ns/credentials/v2",
        }, req.Contexts...),
        "type":     req.CredentialTypes,
        "issuer":   c.cfg.Issuer.DID,
        "validFrom": time.Now().UTC().Format(time.RFC3339),
    }
    
    // Parse document data into credentialSubject
    var subject map[string]any
    if err := json.Unmarshal(req.DocumentData, &subject); err != nil {
        return nil, fmt.Errorf("failed to parse document data: %w", err)
    }
    
    if req.SubjectID != "" {
        subject["id"] = req.SubjectID
    }
    cred["credentialSubject"] = subject
    
    // Marshal to JSON for signing
    credBytes, err := json.Marshal(cred)
    if err != nil {
        return nil, err
    }
    
    // Create RDF credential
    rdfCred, err := credential.NewRDFCredentialFromJSON(credBytes, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to create RDF credential: %w", err)
    }
    
    // Sign based on cryptosuite
    var signedCred *credential.RDFCredential
    
    switch req.Cryptosuite {
    case "ecdsa-rdfc-2019", "":
        suite := ecdsa.NewSuite()
        signedCred, err = suite.Sign(rdfCred, c.signingKey, &ecdsa.SignOptions{
            VerificationMethod: c.cfg.Issuer.VerificationMethod,
            ProofPurpose:       "assertionMethod",
            Created:            time.Now().UTC(),
        })
        
    case "ecdsa-sd-2023":
        sdSuite := ecdsa.NewSdSuite()
        signedCred, err = sdSuite.Sign(rdfCred, c.signingKey, &ecdsa.SdSignOptions{
            VerificationMethod: c.cfg.Issuer.VerificationMethod,
            ProofPurpose:       "assertionMethod",
            Created:            time.Now().UTC(),
            MandatoryPointers:  req.MandatoryPointers,
        })
        
    default:
        return nil, fmt.Errorf("unsupported cryptosuite: %s", req.Cryptosuite)
    }
    
    if err != nil {
        return nil, fmt.Errorf("failed to sign credential: %w", err)
    }
    
    // Get signed credential as JSON
    signedJSON, err := signedCred.ToJSON()
    if err != nil {
        return nil, fmt.Errorf("failed to serialize signed credential: %w", err)
    }
    
    return &CreateVC20Reply{
        Credential: signedJSON,
    }, nil
}
```

## Feature Parity Matrix

| Feature | SD-JWT | mDoc | W3C VC (Status) |
|---------|--------|------|-----------------|
| **Issuance** | ✅ | ✅ | ✅ Complete |
| **Verification** | ✅ | ✅ | ✅ Complete |
| **Selective Disclosure** | ✅ | ✅ | ✅ (ecdsa-sd-2023) |
| **Holder Binding** | ✅ (cnf) | ✅ (device key) | ⏳ (proof.challenge) |
| **Revocation** | ✅ (status list) | ✅ | ⏳ (BitstringStatusList) |
| **DCQL Query** | ✅ | ✅ | 🔄 Partial |
| **Presentation** | ✅ | ✅ | ⏳ Phase 4 |
| **Trust Framework** | ✅ (ETSI TL) | ✅ | ⏳ Phase 3.2 |

## Testing Requirements

### Unit Tests (Implemented)

The following tests are implemented in `pkg/openid4vp/vc20_handler_test.go`:

```go
func TestVC20Handler_VerifyAndExtract_ECDSA2019(t *testing.T)          // ✅
func TestVC20Handler_VerifyAndExtract_ECDSA2019_WithStaticKey(t *testing.T) // ✅
func TestVC20Handler_VerifyAndExtract_ECDSASD2023_Base(t *testing.T)   // ✅
func TestVC20Handler_VerifyAndExtract_EdDSA2022(t *testing.T)          // ✅
func TestVC20Handler_CreateCredential_ECDSA2019(t *testing.T)          // ✅
func TestVC20Handler_CreateCredential_ECDSASD2023(t *testing.T)        // ✅
func TestVC20Handler_CreateCredential_EdDSA2022(t *testing.T)          // ✅
```

Issuer handler tests in `internal/issuer/apiv1/handlers_vc20_test.go`:

```go
func TestMakeVC20_ECDSA2019(t *testing.T)                              // ✅
func TestMakeVC20_ECDSASD2023(t *testing.T)                            // ✅
func TestMakeVC20_DefaultCryptosuite(t *testing.T)                     // ✅
func TestMakeVC20_InvalidCryptosuite(t *testing.T)                     // ✅
func TestMakeVC20_InvalidDocumentData(t *testing.T)                    // ✅
func TestMakeVC20_RoundTrip(t *testing.T)                              // ✅
```

### Integration Tests (Pending)
func TestOpenID4VP_VC20_CrossFormat(t *testing.T) // Wallet with SD-JWT, verifier requests ldp_vc
```

### Test Vectors
- W3C VC Data Integrity test suite credentials
- SAL eApostille test vectors (real-world validation)
- EBSI conformance test vectors

# W3C VC Data Integrity OpenID4VP Handler - Implementation Specification

This document provides detailed implementation specifications for integrating W3C Verifiable Credentials Data Integrity with OpenID4VP, ensuring feature parity with existing SD-JWT and mDoc handlers.

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

## DID Key Resolver Implementation

```go
// pkg/keyresolver/did_resolver.go

package keyresolver

import (
    "context"
    "crypto"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "strings"
    "time"
    
    "github.com/jellydator/ttlcache/v3"
    "github.com/multiformats/go-multibase"
)

// DIDDocument represents a DID Document
type DIDDocument struct {
    Context            []string             `json:"@context"`
    ID                 string               `json:"id"`
    VerificationMethod []VerificationMethod `json:"verificationMethod"`
    Authentication     []any                `json:"authentication,omitempty"`
    AssertionMethod    []any                `json:"assertionMethod,omitempty"`
}

// VerificationMethod represents a verification method in a DID Document
type VerificationMethod struct {
    ID                 string `json:"id"`
    Type               string `json:"type"`
    Controller         string `json:"controller"`
    PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
    PublicKeyJwk       *JWK   `json:"publicKeyJwk,omitempty"`
}

// JWK represents a JSON Web Key
type JWK struct {
    Kty string `json:"kty"`
    Crv string `json:"crv,omitempty"`
    X   string `json:"x,omitempty"`
    Y   string `json:"y,omitempty"`
}

// DIDKeyResolver resolves DID verification methods to public keys
type DIDKeyResolver struct {
    httpClient *http.Client
    cache      *ttlcache.Cache[string, *DIDDocument]
}

// NewDIDKeyResolver creates a new resolver
func NewDIDKeyResolver() *DIDKeyResolver {
    return &DIDKeyResolver{
        httpClient: &http.Client{Timeout: 10 * time.Second},
        cache: ttlcache.New[string, *DIDDocument](
            ttlcache.WithTTL[string, *DIDDocument](5 * time.Minute),
        ),
    }
}

// ResolveKey resolves a verification method to a public key
func (r *DIDKeyResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error) {
    // Parse verification method
    did, fragment, err := r.parseVerificationMethod(verificationMethod)
    if err != nil {
        return nil, err
    }
    
    // Determine DID method
    method := r.extractMethod(did)
    
    switch method {
    case "key":
        return r.resolveDidKey(did, fragment)
    case "web":
        return r.resolveDidWeb(ctx, did, fragment)
    default:
        return nil, fmt.Errorf("unsupported DID method: %s", method)
    }
}

// resolveDidKey resolves did:key (self-contained, no network fetch)
func (r *DIDKeyResolver) resolveDidKey(did, fragment string) (crypto.PublicKey, error) {
    // Extract multibase-encoded public key from DID
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
    
    // Parse multicodec prefix and extract key
    // 0xed01 = Ed25519, 0x1200 = P-256, 0x1201 = P-384, etc.
    return r.parseMulticodecKey(keyBytes)
}

// resolveDidWeb resolves did:web by fetching DID document
func (r *DIDKeyResolver) resolveDidWeb(ctx context.Context, did, fragment string) (crypto.PublicKey, error) {
    // Check cache
    if doc := r.cache.Get(did); doc != nil {
        return r.extractKeyFromDocument(doc.Value(), fragment)
    }
    
    // Build URL from did:web
    // did:web:example.com -> https://example.com/.well-known/did.json
    // did:web:example.com:path:to -> https://example.com/path/to/did.json
    url, err := r.didWebToURL(did)
    if err != nil {
        return nil, err
    }
    
    // Fetch DID document
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept", "application/did+json, application/json")
    
    resp, err := r.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch DID document: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("DID document fetch failed: %d", resp.StatusCode)
    }
    
    var doc DIDDocument
    if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
        return nil, fmt.Errorf("failed to parse DID document: %w", err)
    }
    
    // Cache document
    r.cache.Set(did, &doc, ttlcache.DefaultTTL)
    
    return r.extractKeyFromDocument(&doc, fragment)
}

// extractKeyFromDocument extracts a public key from a DID document
func (r *DIDKeyResolver) extractKeyFromDocument(doc *DIDDocument, fragment string) (crypto.PublicKey, error) {
    targetID := doc.ID + "#" + fragment
    
    for _, vm := range doc.VerificationMethod {
        if vm.ID == targetID || vm.ID == fragment {
            return r.parseVerificationMethodKey(&vm)
        }
    }
    
    return nil, fmt.Errorf("verification method not found: %s", targetID)
}

// parseVerificationMethodKey extracts public key from verification method
func (r *DIDKeyResolver) parseVerificationMethodKey(vm *VerificationMethod) (crypto.PublicKey, error) {
    // Try publicKeyMultibase first
    if vm.PublicKeyMultibase != "" {
        _, keyBytes, err := multibase.Decode(vm.PublicKeyMultibase)
        if err != nil {
            return nil, err
        }
        return r.parseMulticodecKey(keyBytes)
    }
    
    // Try publicKeyJwk
    if vm.PublicKeyJwk != nil {
        return r.parseJWKKey(vm.PublicKeyJwk)
    }
    
    return nil, fmt.Errorf("no supported key format in verification method")
}

// parseJWKKey parses a JWK to a public key
func (r *DIDKeyResolver) parseJWKKey(jwk *JWK) (crypto.PublicKey, error) {
    switch jwk.Kty {
    case "EC":
        return r.parseECJWK(jwk)
    case "OKP":
        return r.parseOKPJWK(jwk)
    default:
        return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
    }
}

// parseECJWK parses an EC JWK
func (r *DIDKeyResolver) parseECJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
    var curve elliptic.Curve
    switch jwk.Crv {
    case "P-256":
        curve = elliptic.P256()
    case "P-384":
        curve = elliptic.P384()
    case "P-521":
        curve = elliptic.P521()
    default:
        return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
    }
    
    x, err := base64.RawURLEncoding.DecodeString(jwk.X)
    if err != nil {
        return nil, err
    }
    y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
    if err != nil {
        return nil, err
    }
    
    return &ecdsa.PublicKey{
        Curve: curve,
        X:     new(big.Int).SetBytes(x),
        Y:     new(big.Int).SetBytes(y),
    }, nil
}
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

| Feature | SD-JWT | mDoc | W3C VC (planned) |
|---------|--------|------|------------------|
| **Issuance** | ✅ | ✅ | 🔄 Phase 2 |
| **Verification** | ✅ | ✅ | 🔄 Phase 1 |
| **Selective Disclosure** | ✅ | ✅ | 🔄 (ecdsa-sd-2023) |
| **Holder Binding** | ✅ (cnf) | ✅ (device key) | 🔄 (proof.challenge) |
| **Revocation** | ✅ (status list) | ✅ | 🔄 (BitstringStatusList) |
| **DCQL Query** | ✅ | ✅ | 🔄 Phase 1.3 |
| **Presentation** | ✅ | ✅ | 🔄 Phase 4 |
| **Trust Framework** | ✅ (ETSI TL) | ✅ | 🔄 Phase 3.2 |

## Testing Requirements

### Unit Tests
```go
// pkg/openid4vp/vc20_handler_test.go

func TestVC20Handler_VerifyAndExtract_ECDSA2019(t *testing.T)
func TestVC20Handler_VerifyAndExtract_ECDSASD2023_Base(t *testing.T)
func TestVC20Handler_VerifyAndExtract_ECDSASD2023_Derived(t *testing.T)
func TestVC20Handler_VerifyAndExtract_UntrustedIssuer(t *testing.T)
func TestVC20Handler_VerifyAndExtract_ExpiredCredential(t *testing.T)
func TestVC20Handler_VerifyAndExtract_InvalidSignature(t *testing.T)
```

### Integration Tests
```go
// internal/verifier/apiv1/handler_openid4vp_vc20_test.go

func TestOpenID4VP_VC20_EndToEnd(t *testing.T)
func TestOpenID4VP_VC20_SelectiveDisclosure(t *testing.T)
func TestOpenID4VP_VC20_CrossFormat(t *testing.T) // Wallet with SD-JWT, verifier requests ldp_vc
```

### Test Vectors
- W3C VC Data Integrity test suite credentials
- SAL eApostille test vectors (real-world validation)
- EBSI conformance test vectors

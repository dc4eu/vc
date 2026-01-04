# ADR-14: W3C Verifiable Credentials Data Integrity Integration Plan

## Status

Proposed

## Context

The vc repository currently supports two credential formats for OpenID4VCI/VP flows:
- **SD-JWT VC** (`vc+sd-jwt`, `dc+sd-jwt`) - IETF SD-JWT based credentials
- **mDL/mDoc** (`mso_mdoc`) - ISO 18013-5 mobile document credentials

We have recently implemented and fixed the W3C Verifiable Credentials Data Integrity 1.0 specification in `pkg/vc20/`, including:
- `ecdsa-rdfc-2019` - Standard ECDSA Data Integrity proofs
- `ecdsa-sd-2023` - ECDSA Selective Disclosure cryptosuite (BASE and DERIVED proofs)

This ADR outlines the plan for integrating W3C VC Data Integrity credentials into the issuer and verifier infrastructure with full OpenID4VCI/VP compliance and feature parity with existing formats.

## Decision

Integrate W3C VC Data Integrity as a third credential format alongside SD-JWT and mDoc, following the established handler patterns.

## Integration Plan

### Phase 1: OpenID4VP Handler (Verifier Side)

**Goal**: Enable verifiers to accept W3C VC Data Integrity presentations.

#### 1.1 Create VC20 Handler

Create `pkg/openid4vp/vc20_handler.go` following the established pattern:

```go
package openid4vp

// VC20Handler verifies W3C VC 2.0 Data Integrity credentials
type VC20Handler struct {
    // KeyResolver resolves issuer public keys from verification methods
    KeyResolver VC20KeyResolver
    
    // TrustedIssuers is an optional allowlist of trusted issuer DIDs
    TrustedIssuers []string
    
    // ContextLoader for JSON-LD context resolution
    ContextLoader ld.DocumentLoader
    
    // CheckRevocation enables status list checks
    CheckRevocation bool
}

// VC20KeyResolver resolves public keys for W3C VC verification
type VC20KeyResolver interface {
    // ResolveKey resolves a verification method to a public key
    ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
}

// VC20VerificationResult contains the verified credential data
type VC20VerificationResult struct {
    Issuer           string
    Subject          string
    Types            []string
    IssuanceDate     time.Time
    ExpirationDate   *time.Time
    CredentialSubject map[string]any
    ProofType        string  // "ecdsa-rdfc-2019" or "ecdsa-sd-2023"
    DisclosedClaims  []string // For selective disclosure
}

// VerifyAndExtract verifies a W3C VC VP token and extracts claims
func (h *VC20Handler) VerifyAndExtract(ctx context.Context, vpToken string) (*VC20VerificationResult, error)
```

**Implementation Tasks**:
1. Parse VP token as JSON-LD (may be base64url encoded or plain JSON)
2. Extract embedded Verifiable Credentials
3. Verify Data Integrity proofs using `pkg/vc20/crypto/ecdsa`
4. Handle both `ecdsa-rdfc-2019` and `ecdsa-sd-2023` cryptosuites
5. For SD credentials, reconstruct disclosed claims from DERIVED proof
6. Validate timestamps (created, expires)
7. Optional: Check credential status via `credentialStatus`

#### 1.2 Credential Format Identifier

Register format identifiers per OpenID4VC Appendix A:

| Format Identifier | Description |
|-------------------|-------------|
| `ldp_vc` | W3C VC Data Model 1.1 with Data Integrity proof |
| `vc+ld+json` | W3C VC Data Model 2.0 with Data Integrity proof |

For DCQL queries, add format-specific metadata:

```json
{
  "format": "ldp_vc",
  "meta": {
    "cryptosuite_values": ["ecdsa-rdfc-2019", "ecdsa-sd-2023"]
  }
}
```

#### 1.3 DCQL Support

Update `pkg/openid4vp/dcql.go` to support W3C VC queries:

```go
type MetaQuery struct {
    // For SD-JWT format
    VCTValues []string `json:"vct_values,omitempty"`
    
    // For W3C VC format (ldp_vc, vc+ld+json)
    TypeValues       []string `json:"type_values,omitempty"`
    CryptosuiteValues []string `json:"cryptosuite_values,omitempty"`
}
```

### Phase 2: OpenID4VCI Support (Issuer Side)

**Goal**: Enable issuers to issue W3C VC Data Integrity credentials.

#### 2.1 Issuer Metadata Configuration

Add VC20 credential configuration to issuer metadata:

```yaml
credential_configurations_supported:
  pid_ldp_vc:
    format: "ldp_vc"
    cryptographic_binding_methods_supported:
      - "did:key"
      - "did:web"
    credential_signing_alg_values_supported:
      - "ES256"
      - "ES384"
    proof_types_supported:
      jwt:
        proof_signing_alg_values_supported:
          - "ES256"
    credential_definition:
      type:
        - "VerifiableCredential"
        - "PersonIdentificationData"
      "@context":
        - "https://www.w3.org/ns/credentials/v2"
        - "https://example.org/pid/v1"
```

#### 2.2 Credential Issuance Handler

Add to `internal/issuer/apiv1/handlers.go`:

```go
// CreateVC20Request is the request for W3C VC issuance
type CreateVC20Request struct {
    DocumentData       []byte            `json:"document_data" validate:"required"`
    Scope              string            `json:"scope" validate:"required"`
    CredentialTypes    []string          `json:"credential_types" validate:"required"`
    SubjectDID         string            `json:"subject_did,omitempty"` // For DID binding
    Cryptosuite        string            `json:"cryptosuite"` // "ecdsa-rdfc-2019" or "ecdsa-sd-2023"
    MandatoryPointers  []string          `json:"mandatory_pointers,omitempty"` // For SD
}

// CreateVC20Reply is the reply for W3C VC issuance
type CreateVC20Reply struct {
    Credential []byte `json:"credential"` // JSON-LD credential bytes
}

// MakeVC20 creates a W3C VC Data Integrity credential
func (c *Client) MakeVC20(ctx context.Context, req *CreateVC20Request) (*CreateVC20Reply, error)
```

**Implementation Tasks**:
1. Build JSON-LD credential structure from document data
2. Add appropriate `@context` references
3. Set `issuer` to configured DID or URL
4. Add `credentialSubject` with holder binding if provided
5. Sign using appropriate cryptosuite (`ecdsa-rdfc-2019` or `ecdsa-sd-2023`)
6. For SD: Apply mandatory pointers during BASE proof generation

#### 2.3 Format Routing in API Gateway

Update `internal/apigw/apiv1/handlers_issuer.go`:

```go
switch format {
case "mso_mdoc":
    return c.issueMDoc(ctx, ...)
case "vc+sd-jwt", "dc+sd-jwt":
    return c.issueSDJWT(ctx, ...)
case "ldp_vc", "vc+ld+json":
    return c.issueVC20(ctx, ...)
default:
    return nil, errors.New("unsupported format")
}
```

### Phase 3: Key Resolution and Trust

**Goal**: Enable DID-based key resolution for W3C VC verification.

#### 3.1 DID Key Resolver

Create `pkg/keyresolver/did_resolver.go`:

```go
package keyresolver

// DIDKeyResolver resolves public keys from DID documents
type DIDKeyResolver struct {
    // HTTPClient for fetching DID documents
    HTTPClient *http.Client
    
    // Cache for resolved DID documents
    Cache *ttlcache.Cache[string, *DIDDocument]
    
    // SupportedMethods lists supported DID methods
    SupportedMethods []string // e.g., ["did:key", "did:web", "did:ebsi"]
}

// ResolveKey resolves a verification method URI to a public key
func (r *DIDKeyResolver) ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
```

**Supported DID Methods**:
1. `did:key` - Self-contained, no network fetch needed
2. `did:web` - Fetch `.well-known/did.json` from domain
3. `did:ebsi` - EBSI DID resolver (EU trust framework)

#### 3.2 Trust Framework Integration

For ETSI TL (Trusted List) integration:

```go
type TrustFramework interface {
    // IsTrustedIssuer checks if an issuer is in a trusted list
    IsTrustedIssuer(ctx context.Context, issuerDID string, tlURL string) (bool, error)
}
```

### Phase 4: Verifiable Presentations

**Goal**: Support W3C VP creation for holder-initiated presentations.

#### 4.1 Presentation Builder

Add W3C VP support to `pkg/openid4vp/presentation_builder.go`:

```go
// BuildVC20Presentation creates a W3C Verifiable Presentation
func (b *PresentationBuilder) BuildVC20Presentation(
    credentials [][]byte,    // Array of VC JSON bytes
    holderDID string,
    nonce string,
    domain string,
) ([]byte, error)
```

**For Selective Disclosure (`ecdsa-sd-2023`)**:

```go
// DeriveVC20Credential creates a derived credential with selective disclosure
func DeriveVC20Credential(
    baseCredential []byte,   // BASE proof credential
    selectivePointers []string, // JSON pointers to disclose
    holderKey *ecdsa.PrivateKey, // For holder binding proof
) ([]byte, error)
```

### Phase 5: Status List Support

**Goal**: Enable revocation checking for W3C VCs.

#### 5.1 BitstringStatusList

Implement W3C BitstringStatusList 2024:

```go
// BitstringStatusListCredential represents a status list credential
type BitstringStatusListCredential struct {
    Context           []string `json:"@context"`
    ID                string   `json:"id"`
    Type              []string `json:"type"`
    Issuer            string   `json:"issuer"`
    ValidFrom         string   `json:"validFrom"`
    CredentialSubject struct {
        ID           string `json:"id"`
        Type         string `json:"type"` // "BitstringStatusList"
        StatusPurpose string `json:"statusPurpose"` // "revocation"
        EncodedList  string `json:"encodedList"` // GZIP + Base64
    } `json:"credentialSubject"`
}

// CheckStatus verifies credential status against the status list
func CheckBitstringStatus(statusListURL string, statusIndex int) (bool, error)
```

### Implementation Order

| Phase | Component | Priority | Effort |
|-------|-----------|----------|--------|
| 1.1 | VC20Handler | High | 2-3 days |
| 1.2 | Format identifiers | High | 0.5 days |
| 1.3 | DCQL support | Medium | 1 day |
| 2.1 | Issuer metadata | High | 0.5 days |
| 2.2 | MakeVC20 handler | High | 2 days |
| 2.3 | Format routing | High | 0.5 days |
| 3.1 | DID resolver | High | 2 days |
| 3.2 | Trust framework | Medium | 1-2 days |
| 4.1 | VP builder | Medium | 1 day |
| 5.1 | Status list | Low | 2 days |

**Total estimated effort**: 12-15 days

### Testing Strategy

#### Unit Tests
- `pkg/openid4vp/vc20_handler_test.go` - Handler verification tests
- `pkg/keyresolver/did_resolver_test.go` - DID resolution tests
- Integration with existing W3C conformance test vectors

#### Integration Tests
- End-to-end issuance flow with `ldp_vc` format
- End-to-end presentation/verification flow
- Cross-format interoperability (SD-JWT wallet receiving VC20 request)

#### Conformance Tests
- W3C VC Data Integrity test suite
- OpenID4VCI conformance tests (when available for ldp_vc)
- OpenID4VP conformance tests

### Configuration Example

```yaml
# Verifier configuration
verifier:
  openid4vp:
    supported_formats:
      - format: "vc+sd-jwt"
        alg_values: ["ES256"]
      - format: "mso_mdoc"
        alg_values: [-7]  # ES256 as COSE alg
      - format: "ldp_vc"
        cryptosuites: ["ecdsa-rdfc-2019", "ecdsa-sd-2023"]
    
    trusted_issuers:
      - "did:web:issuer.example.com"
      - "did:ebsi:example"
    
    trust_frameworks:
      - type: "etsi_tl"
        url: "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

# Issuer configuration  
issuer:
  credential_configurations:
    pid_ldp_vc:
      format: "ldp_vc"
      cryptosuite: "ecdsa-sd-2023"
      mandatory_pointers:
        - "/issuer"
        - "/validFrom"
        - "/credentialSubject/type"
      signing_key_id: "did:web:issuer.example.com#key-1"
```

## Consequences

### Positive
- Full W3C VC Data Model 2.0 compliance
- Selective disclosure via `ecdsa-sd-2023` cryptosuite
- DID-based trust model integration
- Feature parity with SD-JWT and mDoc formats
- Prepared for EUDI Wallet interoperability

### Negative
- Increased complexity in format handling
- JSON-LD processing overhead
- Additional dependencies (DID resolvers, context loaders)
- Larger credential sizes compared to SD-JWT

### Risks
- JSON-LD canonicalization edge cases (mitigated by comprehensive testing)
- DID resolution availability/latency (mitigated by caching)
- Evolving W3C specifications (monitor spec updates)

## References

- [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C VC Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [W3C ECDSA Cryptosuite v1.0](https://www.w3.org/TR/vc-di-ecdsa/)
- [OpenID4VCI Draft 14](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [OpenID4VP Draft 21](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
- [DCQL (Digital Credentials Query Language)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l)
- ADR-10 through ADR-13: ECDSA-SD-2023 implementation learnings

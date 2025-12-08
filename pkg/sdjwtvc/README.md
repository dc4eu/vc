# SD-JWT VC Package (sdjwtvc)

This package implements **SD-JWT-based Verifiable Credentials (SD-JWT VC)** per [draft-ietf-oauth-sd-jwt-vc-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/).

## Specifications

This implementation is compliant with:

- **SD-JWT VC draft-13**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/
- **SD-JWT draft-22**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/

## Key Features

### SD-JWT VC Compliance (draft-13)

#### Media Type (Section 3.1)
- Uses `application/dc+sd-jwt` media type
- JWT header `typ` claim: `dc+sd-jwt`
- Also accepts `vc+sd-jwt` during transition period

#### Required Claims (Section 3.2.2)
- `vct`: Verifiable Credential Type identifier (REQUIRED)
- `iss`: Issuer identifier (OPTIONAL but recommended)
- `iat`: Issuance time (OPTIONAL)
- `exp`: Expiration time (OPTIONAL)
- `cnf`: Confirmation method for Key Binding (OPTIONAL, REQUIRED for Key Binding)
- `_sd_alg`: Hash algorithm (automatically set based on hash method used)

#### Type Metadata (Section 6)
Full support for **VCTM (Verifiable Credential Type Metadata)**:

- **Type identification** (`vct` field)
- **Display metadata** (Section 8):
  - Locale-specific rendering
  - Simple rendering (logo, colors)
  - SVG templates with properties
- **Claim metadata** (Section 9):
  - Claim paths for nested structures
  - Display labels per locale
  - Selective disclosure rules (`sd`: "always", "allowed", "never")
  - Mandatory claim indicators
  - SVG template placeholders
- **Type extension** (`extends` field)
- **Integrity protection** (Section 7):
  - Subresource Integrity hashes
  - `vct#integrity`, `extends#integrity`, `uri#integrity`

### SD-JWT Core Features (draft-22)

- **Selective Disclosure**: 
  - Object properties (Section 4.2.1)
  - Array elements (Section 4.2.2)
  - Recursive structures (Section 4.2.6)
- **Security**:
  - Cryptographically secure random salts (128-bit entropy)
  - Decoy digests to obscure claim count (Section 4.2.5)
  - Hash-based disclosure protection
- **Hash Algorithms**:
  - SHA-256 (default)
  - SHA-384
  - SHA-512
  - SHA3-256
  - SHA3-512

## Usage Examples

### Creating an SD-JWT VC

```go
import (
    "crypto/sha256"
    "vc/pkg/sdjwtvc"
)

// Initialize client
client := sdjwtvc.New()

// Define credential type metadata
vctm := &sdjwtvc.VCTM{
    VCT: "https://example.com/credentials/identity",
    Name: "Identity Credential",
    Claims: []sdjwtvc.Claim{
        {
            Path: []*string{strPtr("given_name")},
            SD: "always", // Always selectively disclosable
        },
        {
            Path: []*string{strPtr("family_name")},
            SD: "always",
        },
    },
}

// Create credential
credential, err := client.BuildCredential(
    "https://issuer.example.com",
    "key-1",
    privateKey,
    "https://example.com/credentials/identity",
    documentData,
    holderPublicKeyJWK,
    vctm,
    &sdjwtvc.CredentialOptions{
        DecoyDigests:   3,   // Add 3 decoy digests for privacy
        ExpirationDays: 365, // Valid for 1 year
    },
)
```

### Parsing an SD-JWT (Without Verification)

For scenarios where you need to extract claims and disclosures without signature verification:

```go
import "vc/pkg/sdjwtvc"

// Parse token into structured data
parsed, err := sdjwtvc.Token(sdJWT).Parse()
if err != nil {
    log.Fatal(err)
}

// Access all claims (including disclosed selective disclosures)
fmt.Println("Claims:", parsed.Claims)
fmt.Println("Issuer:", parsed.Claims["iss"])
fmt.Println("VCT:", parsed.Claims["vct"])

// Access raw disclosures
fmt.Println("Number of disclosures:", len(parsed.Disclosures))
for i, disclosure := range parsed.Disclosures {
    fmt.Printf("Disclosure %d: %s\n", i, disclosure)
}

// Access header
fmt.Println("Algorithm:", parsed.Header["alg"])
fmt.Println("Type:", parsed.Header["typ"])

// Access key binding if present
if len(parsed.KeyBinding) > 0 {
    fmt.Println("Has key binding JWT")
}
```

**Note**: `Token.Parse()` does NOT verify signatures or validate claims. Use `ParseAndVerify()` for security-critical operations.

### Verifying an SD-JWT VC

```go
import (
    "vc/pkg/sdjwtvc"
)

client := sdjwtvc.New()

// Parse and verify the credential
result, err := client.ParseAndVerify(
    sdJWT,              // The SD-JWT string
    issuerPublicKey,    // Issuer's public key for signature verification
    &sdjwtvc.VerificationOptions{
        ValidateTime:     true,                 // Validate exp/iat/nbf
        AllowedClockSkew: 5 * time.Minute,      // Allow 5 min clock skew
    },
)

if err != nil {
    // Fatal error (signature invalid, expired, etc.)
    log.Fatal(err)
}

if !result.Valid {
    // Validation failed
    for _, err := range result.Errors {
        log.Println("Validation error:", err)
    }
    return
}

// Access verified data
fmt.Println("Issuer:", result.Claims["iss"])
fmt.Println("Credential Type:", result.Claims["vct"])

// Access disclosed claims
for claim, value := range result.DisclosedClaims {
    fmt.Printf("Disclosed %s: %v\n", claim, value)
}

// Check VCTM if present
if result.VCTM != nil {
    fmt.Println("Type:", result.VCTM.VCT)
    fmt.Println("Display Name:", result.VCTM.Name)
}
```

### Verifying SD-JWT with Key Binding

```go
client := sdjwtvc.New()

// Verify SD-JWT+KB (includes Key Binding JWT)
result, err := client.ParseAndVerify(
    sdJWTPlusKB,        // SD-JWT with KB-JWT appended
    issuerPublicKey,
    &sdjwtvc.VerificationOptions{
        RequireKeyBinding: true,                        // KB-JWT must be present
        ExpectedNonce:     "verifier-nonce-12345",      // Validate nonce
        ExpectedAudience:  "https://verifier.example.com", // Validate audience
    },
)

if err != nil {
    log.Fatal(err)
}

if result.KeyBindingValid {
    fmt.Println("Key binding verified!")
    fmt.Println("Nonce:", result.KeyBindingClaims["nonce"])
    fmt.Println("Audience:", result.KeyBindingClaims["aud"])
}
```

### Advanced: Custom Verification

```go
// Skip time validation for testing or specific use cases
result, err := client.ParseAndVerify(
    sdJWT,
    issuerPublicKey,
    &sdjwtvc.VerificationOptions{
        ValidateTime: false, // Don't check exp/iat/nbf
    },
)

// Access individual disclosures
for _, disclosure := range result.Disclosures {
    fmt.Printf("Claim: %s\n", disclosure.Claim)
    fmt.Printf("  Value: %v\n", disclosure.Value)
    fmt.Printf("  Salt: %s\n", disclosure.Salt)
    fmt.Printf("  Hash: %s\n", disclosure.Hash)
}
```

### Creating SD-JWT with Decoy Digests

```go
// Create credential with decoy digests for privacy
credential, err := client.BuildCredential(
    issuer,
    keyID,
    privateKey,
    credentialType,
    documentData,
    holderJWK,
    vctm,
    &sdjwtvc.CredentialOptions{
        DecoyDigests:   5,   // Add 5 decoy hashes per _sd array
        ExpirationDays: 365,
    },
)
```

## API Reference

### Credential Creation

#### `BuildCredential`

```go
func (c *Client) BuildCredential(
    issuer string,
    keyID string,
    privateKey any,
    credentialType string,
    documentData []byte,
    holderJWK map[string]any,
    vctm *VCTM,
    opts *CredentialOptions,
) (string, error)
```

Creates a complete SD-JWT VC credential.

**Parameters:**
- `issuer`: Issuer identifier (used in `iss` claim)
- `keyID`: Key identifier for JWT header `kid`
- `privateKey`: Signing key (*ecdsa.PrivateKey or *rsa.PrivateKey)
- `credentialType`: Credential type identifier (used in `vct` claim)
- `documentData`: JSON-encoded credential claims
- `holderJWK`: Holder's public key in JWK format (for key binding)
- `vctm`: Verifiable Credential Type Metadata
- `opts`: Optional parameters (nil for defaults)

**Returns:** Complete SD-JWT string with disclosures

### Credential Verification

#### `ParseAndVerify`

```go
func (c *Client) ParseAndVerify(
    sdJWT string,
    publicKey any,
    opts *VerificationOptions,
) (*VerificationResult, error)
```

Parses and verifies an SD-JWT VC credential.

**Parameters:**
- `sdJWT`: The SD-JWT string (format: `<JWT>~<Disclosure1>~...~[<KB-JWT>]`)
- `publicKey`: Issuer's public key (*ecdsa.PublicKey or *rsa.PublicKey)
- `opts`: Verification options (nil for defaults)

**Returns:** `VerificationResult` with parsed claims and validity status

#### `VerificationResult`

```go
type VerificationResult struct {
    Valid             bool              // Overall validity (true if no errors)
    Header            map[string]any    // JWT header
    Claims            map[string]any    // All claims (including disclosed)
    DisclosedClaims   map[string]any    // Only selectively disclosed claims
    Disclosures       []Disclosure      // Parsed disclosure structures
    VCTM              *VCTM            // Type metadata (if present in header)
    KeyBindingValid   bool              // Whether KB-JWT signature verified
    KeyBindingClaims  map[string]any    // KB-JWT claims (if present)
    Errors            []error           // Any validation errors encountered
}
```

#### `VerificationOptions`

```go
type VerificationOptions struct {
    RequireKeyBinding bool              // Whether KB-JWT must be present
    ExpectedNonce     string            // Nonce to validate in KB-JWT
    ExpectedAudience  string            // Audience to validate in KB-JWT
    AllowedClockSkew  time.Duration     // Allowed time skew (default: 5 min)
    ValidateTime      bool              // Whether to validate exp/iat (default: true)
}
```

### Key Binding

#### `CreateKeyBindingJWT`

```go
func CreateKeyBindingJWT(
    sdJWT string,
    nonce string,
    audience string,
    holderPrivateKey any,
    hashAlg string,
) (string, error)
```

Creates a Key Binding JWT to prove possession of the holder's key.

**Parameters:**
- `sdJWT`: The SD-JWT string (without KB-JWT)
- `nonce`: Freshness value from verifier
- `audience`: Verifier's identifier
- `holderPrivateKey`: Holder's private key
- `hashAlg`: Hash algorithm ("sha-256", "sha-384", "sha-512", etc.)

**Returns:** KB-JWT string to append to SD-JWT

## Compliance Notes
    vctm,
    &sdjwtvc.CredentialOptions{
        DecoyDigests: 2,      // Add 2 decoy digests per _sd array
        ExpirationDays: 365,  // Valid for 1 year
    },
)
```

### Type Metadata Structure

```go
vctm := &sdjwtvc.VCTM{
    VCT: "https://example.com/education_credential",
    Name: "Education Credential",
    Description: "University degree credential",
    
    // Display information
    Display: []sdjwtvc.VCTMDisplay{
        {
            Lang: "en-US",
            Name: "University Degree",
            Description: "Official academic credential",
            Rendering: sdjwtvc.Rendering{
                Simple: sdjwtvc.SimpleRendering{
                    Logo: sdjwtvc.Logo{
                        URI: "https://example.com/logo.png",
                        AltText: "University Logo",
                    },
                    BackgroundColor: "#003366",
                    TextColor: "#FFFFFF",
                },
            },
        },
    },
    
    // Claim metadata
    Claims: []sdjwtvc.Claim{
        {
            Path: []*string{strPtr("degree"), strPtr("type")},
            Display: []sdjwtvc.ClaimDisplay{
                {
                    Lang: "en-US",
                    Label: "Degree Type",
                },
            },
            SD: "never",      // Always disclosed
            Mandatory: true,  // Must be present
        },
        {
            Path: []*string{strPtr("student"), strPtr("email")},
            SD: "always",     // Always selectively disclosable
        },
    },
    
    // Type extension
    Extends: "https://example.com/base_credential",
    ExtendsIntegrity: "sha256-...",
}
```

## Compliance Notes

### Media Type Transition

Per Section 3.2.1 of draft-13:

> "Note that this draft used vc+sd-jwt as the value of the typ header from its inception in July 2023 until November 2024 when it was changed to dc+sd-jwt... It is RECOMMENDED that Verifiers and Holders accept both vc+sd-jwt and dc+sd-jwt as the value of the typ header for a reasonable transitional period."

This package uses `dc+sd-jwt` as the default but systems should accept both values.

### VCTM vs Core SD-JWT

The **VCTM (Verifiable Credential Type Metadata)** is defined in SD-JWT VC specification (Section 6), NOT in the core SD-JWT specification. VCTM provides:

- **Display metadata**: How to render credentials in wallets
- **Claim metadata**: Validation rules and selective disclosure policies
- **Type relationships**: Extension and composition of credential types

The core SD-JWT spec (draft-22) only defines the selective disclosure mechanism itself.

### Hash Algorithm Selection

The `_sd_alg` claim is automatically set based on the hash method provided:

```go
// SHA-256 (most common)
credential, _ := client.MakeCredential(sha256.New(), data, vctm)
// Sets _sd_alg to "sha-256"

// SHA3-512
credential, _ := client.MakeCredential(sha3.New512(), data, vctm)
// Sets _sd_alg to "sha3-512"
```

## Migration from sdjwt3

The package provides conversion utilities for compatibility:

```go
// Convert from sdjwt3 to sdjwtvc
v4VCTM, err := sdjwtvc.ConvertVCTM(v3VCTM)

// Convert back for legacy code
v3VCTM, err := sdjwtvc.ConvertToSDJWT3VCTM(v4VCTM)
```

## References

- [SD-JWT VC Specification (draft-13)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/)
- [SD-JWT Specification (draft-22)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/)
- [IANA Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
- [W3C Subresource Integrity](https://www.w3.org/TR/SRI/)

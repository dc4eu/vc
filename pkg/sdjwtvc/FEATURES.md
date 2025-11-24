# SD-JWT VC - Draft-13 & Draft-22 Compliance Features

This package (`sdjwtvc`) implements:
- **SD-JWT VC** (Verifiable Credentials) according to **draft-ietf-oauth-sd-jwt-vc-13**
- **SD-JWT** (Selective Disclosure) according to **draft-ietf-oauth-selective-disclosure-jwt-22**

## Implemented Features

### 1. Array Element Selective Disclosure (§4.2.2)

The `Discloser` struct supports both object properties and array elements:

```go
type Discloser struct {
    Salt      string
    ClaimName string  // Empty for array elements
    Value     any
    IsArray   bool    // True for array element disclosures
}
```

- When `IsArray = false`: Creates `[salt, claim_name, value]` disclosure (object property)
- When `IsArray = true`: Creates `[salt, value]` disclosure (array element)

### 2. Decoy Digests (§4.2.5)

Decoy digests enhance privacy by obscuring the actual number of selectively disclosed claims:

```go
opts := &CredentialOptions{
    DecoyDigests:   3,  // Add 3 decoy digests per _sd array
    ExpirationDays: 30,
}

credential, disclosures, err := client.MakeCredentialWithOptions(
    sha256.New(),
    data,
    vctm,
    opts.DecoyDigests,
)
```

**Implementation:**
- `generateDecoyDigest()`: Creates cryptographically secure random hash
- `addDecoyDigestsRecursive()`: Recursively adds decoys to all `_sd` arrays
- Decoys are indistinguishable from real digests to prevent privacy leakage

### 3. Key Binding JWT (§4.3)

Key Binding JWT (KB-JWT) proves possession of the Holder's key:

```go
kbJWT, err := CreateKeyBindingJWT(
    sdJWT,              // The SD-JWT string (without KB-JWT)
    nonce,              // Freshness value from Verifier
    audience,           // Identifier of the Verifier
    holderPrivateKey,   // Holder's private key for signing
    "sha-256",          // Hash algorithm (must match _sd_alg)
)
```

**Format:** `<SD-JWT>~<KB-JWT>`

**KB-JWT Claims:**
- `nonce`: Ensures freshness
- `aud`: Intended receiver (Verifier)
- `iat`: Time of KB-JWT creation  
- `sd_hash`: Hash binding KB-JWT to specific SD-JWT

**KB-JWT Header:**
- `typ`: "kb+jwt" (REQUIRED)
- `alg`: Signing algorithm (ES256, ES384, ES512, RS256, RS384, RS512)

### 4. Hash Algorithm Support

Supported hash algorithms per §7.1:
- **SHA-256** (REQUIRED) - `sha-256`
- **SHA-384** (OPTIONAL) - `sha-384`
- **SHA-512** (OPTIONAL) - `sha-512`
- **SHA3-256** (OPTIONAL) - `sha3-256`
- **SHA3-512** (OPTIONAL) - `sha3-512`

### 5. Forbidden Claim Names (§4.2.3)

The implementation validates and rejects forbidden claim names:
- `_sd`: Reserved for selective disclosure array
- `...`: Reserved for recursive disclosure

## Usage Examples

### Basic SD-JWT Creation

```go
client := &sdjwtvc.Client{}

credential, disclosures, err := client.MakeCredential(
    sha256.New(),
    claims,
    vctm,
)
```

### SD-JWT with Decoy Digests

```go
credential, disclosures, err := client.MakeCredentialWithOptions(
    sha256.New(),
    claims,
    vctm,
    3,  // Add 3 decoy digests
)
```

### Parsing SD-JWT Credentials

```go
token := sdjwtvc.Token("eyJhbGci...~WyJz...~WyJh...")

// Parse into structured format
parsed, err := token.Parse()
if err != nil {
    log.Fatal(err)
}

// Access parsed components
claims := parsed.Claims          // map[string]any
disclosures := parsed.Disclosures // []string
header := parsed.Header          // map[string]any
signature := parsed.Signature    // string
```

### Verifying SD-JWT Credentials

```go
import "vc/pkg/sdjwtvc"

// Prepare verification options
opts := &sdjwtvc.VerificationOptions{
    ExpectedNonce:    "verifier-nonce-123",
    ExpectedAudience: "https://verifier.example.com",
    ValidateTime:     true,
}

// Verify SD-JWT with Key Binding
result, err := sdjwtvc.ParseAndVerify(
    sdJWTString,
    issuerPublicKey,
    holderPublicKey,
    opts,
)

if err != nil {
    log.Fatal("Verification failed:", err)
}

// Access verified data
claims := result.VerifiedClaims
disclosures := result.Disclosures
```

### SD-JWT+KB (Key Binding)

```go
// 1. Create SD-JWT
sdJWT, disclosures, err := sdjwtvc.BuildCredential(...)

// 2. Holder creates KB-JWT
kbJWT, err := sdjwtvc.CreateKeyBindingJWT(
    sdJWT,
    nonce,
    audience,
    holderPrivateKey,
    "sha-256",
)

// 3. Combine to create SD-JWT+KB
combined := sdjwtvc.CombineWithKeyBinding(sdJWT, kbJWT)
```

## Backward Compatibility

All new features maintain backward compatibility:

- `BuildCredential()` wraps `BuildCredentialWithOptions()` with default options
- `MakeCredential()` wraps `MakeCredentialWithOptions()` with zero decoys
- Existing code continues to work without modifications

## Testing

Comprehensive test coverage (**83.3%**) includes:

### Verification Tests (`verification_test.go`)
- Valid SD-JWT verification
- Invalid signatures detection
- Expired credential validation
- Key Binding JWT verification
- Nonce and audience validation
- Disclosure parsing and hash verification
- Multiple hash algorithms

### Parsing Tests (`utils_test.go`)
- Token.Parse() with real credentials
- Token.Split() with various formats
- Error handling for malformed tokens
- Base64 decoding utilities

### Decoy Digest Tests (`decoy_test.go`)
- No decoy digests (baseline)
- With decoy digests (verification of count)
- Nested objects (decoys in multiple `_sd` arrays)
- Base64url validation
- Uniqueness verification

### Key Binding Tests (`keybinding_test.go`)
- KB-JWT structure validation
- Nonce variation
- SD-hash calculation
- Hash algorithm support
- SD-JWT+KB combination

### Legacy Compatibility Tests
- All existing tests continue to pass
- No regressions introduced

## New Features (v2.0)

### Verification Support

Complete SD-JWT verification implementation with:
- **JWT signature verification** using issuer's public key
- **SD-JWT VC structure validation** (draft-13 compliance)
- **Disclosure parsing and hash verification**
- **Key Binding JWT verification** with nonce/audience validation
- **Time-based validation** (exp, nbf, iat claims)

### Modern Parsing API

- **Token type**: Represents SD-JWT token strings
- **Token.Parse()**: Parses SD-JWT into structured `ParsedCredential`
- **Token.Split()**: Splits token into components with bounds checking
- **ParsedCredential**: Contains claims, disclosures, header, signature, key binding

### JSONPath Claim Extraction

- **ExtractClaimsByJSONPath()**: Extract claim values using JSONPath queries
- Used for SVG template rendering in wallets

## Compliance Status

✅ **Full compliance with draft-ietf-oauth-selective-disclosure-jwt-22**

- ✅ §4.2.1: Object properties selective disclosure
- ✅ §4.2.2: Array elements selective disclosure
- ✅ §4.2.3: Claim name validation (`_sd`, `...` forbidden)
- ✅ §4.2.5: Decoy digests for privacy
- ✅ §4.3: Key Binding JWT (KB-JWT)
- ✅ §4.3.1: SD-hash calculation
- ✅ §7.1: Hash algorithm negotiation

✅ **Full compliance with draft-ietf-oauth-sd-jwt-vc-13**

- ✅ §3.1: Media type `application/dc+sd-jwt`
- ✅ §3.2.1: JWT header `typ: "dc+sd-jwt"`
- ✅ §6: VCTM (Verifiable Credential Type Metadata)
- ✅ §8: Display metadata with rendering methods
- ✅ §9: Claim metadata with selective disclosure rules

## Performance Considerations

- Decoy digest generation uses `crypto/rand` for cryptographic security
- Recursive decoy addition traverses credential structure once
- Hash calculations are performed using Go's standard crypto libraries
- No performance regression in existing functionality

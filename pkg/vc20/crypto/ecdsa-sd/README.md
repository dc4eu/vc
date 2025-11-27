# ECDSA-SD-2023 Cryptosuite Implementation

This package implements the W3C ECDSA-SD-2023 cryptosuite for Verifiable Credentials 2.0, providing selective disclosure capabilities with ECDSA signatures.

## Overview

ECDSA-SD-2023 is a Data Integrity cryptosuite that enables:
- **Base Proofs**: Issuer creates a proof over the full credential
- **Derived Proofs**: Holder creates selective disclosures revealing only specific fields
- **Mandatory Fields**: Issuer can mark certain fields that MUST always be disclosed

## Architecture

### Key Components

1. **Base Proof Creation** (`base_proof.go`)
   - Signs the complete credential using ECDSA (P-256 or P-384)
   - Includes HMAC key for blank node randomization
   - Stores mandatory pointers for derived proof enforcement
   - Encodes proof components as CBOR with multibase encoding

2. **Derived Proof Creation** (`derived_proof.go`)
   - Selectively discloses credential fields
   - Always includes mandatory fields
   - Re-randomizes blank nodes using base proof HMAC key
   - Creates compact proof with disclosed statement indexes

3. **Verification** (`verify.go`)
   - Verifies base proofs against full credentials
   - Verifies derived proofs with selective disclosure
   - Supports verification method resolution for DID documents

4. **RDF Canonicalization** (`vc20/rdfcanon/`)
   - Uses URDNA2015 algorithm via json-gold library
   - Ensures deterministic N-Quads representation
   - Handles blank node normalization

5. **Multikey Support** (`keys/keys.go`)
   - Encodes/decodes ECDSA public keys to/from Multikey format
   - Supports compressed and uncompressed key formats
   - Compatible with P-256 and P-384 curves

## Mandatory Pointers Behavior

**Important**: Mandatory pointers do NOT affect base proof signatures.

### How It Works

1. **Base Proof Creation**:
   - Signs ALL credential statements (full credential)
   - Stores mandatory pointers in proof metadata
   - Mandatory pointers are NOT used during signing

2. **Derived Proof Creation**:
   - Mandatory fields MUST be included in disclosure
   - Holder cannot create derived proof without revealing mandatory fields
   - Additional selective fields can be included

3. **Derived Proof Verification**:
   - Checks that all mandatory fields are present
   - Verifies disclosed statements match base signature
   - Fails if mandatory fields are missing

### Example

```go
// Issuer creates base proof with mandatory field
options := BaseProofOptions{
    VerificationMethod: "did:example:issuer#key-1",
    ProofPurpose:       "assertionMethod",
    MandatoryPointers:  []string{"/credentialSubject/id"}, // ID must always be shown
}
baseProof, err := suite.CreateBaseProof(credential, issuerPrivateKey, options)

// Holder creates derived proof - MUST include credentialSubject/id
derivedOptions := DerivedProofOptions{
    VerificationMethod: "did:example:holder#key-1",
    SelectivePointers:  []string{"/credentialSubject/name"}, // Optional field
}
// This will automatically include /credentialSubject/id from mandatory pointers
derivedProof, err := suite.CreateDerivedProof(credential, baseProof, derivedOptions)
```

## Test Coverage

### Test Statistics
- **Total Tests**: 98
- **Passing**: 93
- **Skipped**: 5 (W3C test vector placeholders)

### Coverage Areas

#### Base Proof Tests (20+ tests)
- ✅ Basic creation and verification
- ✅ Nil input validation
- ✅ Missing required fields
- ✅ Wrong curve handling (P-384 vs P-256)
- ✅ Custom timestamps
- ✅ Multiple proof support
- ✅ CBOR encoding/decoding
- ✅ Multibase encoding
- ✅ Mandatory pointers storage

#### Derived Proof Tests (25+ tests)
- ✅ Selective disclosure creation
- ✅ Mandatory field enforcement
- ✅ Challenge/domain support
- ✅ Statement index calculation
- ✅ Blank node handling
- ✅ Credential comparison
- ✅ Multiple derivation scenarios
- ✅ Integration tests

#### Edge Cases (30+ tests)
- ✅ Empty mandatory pointers
- ✅ Invalid multibase encoding
- ✅ Malformed CBOR data
- ✅ Wrong CBOR tags
- ✅ Invalid proof values
- ✅ HMAC key validation
- ✅ Null/empty inputs
- ✅ Invalid JSON pointers

#### Multikey Tests (5+ tests)
- ✅ P-256 key encoding/decoding
- ✅ P-384 key encoding/decoding
- ✅ Compressed key support
- ✅ Uncompressed key support
- ✅ Key validation

### W3C Test Vectors

**Status**: Infrastructure created, awaiting full test vectors from W3C spec

Test vector infrastructure includes:
- Key material parsing (P-256 multikey format) ✅
- Test credential from spec Appendix A.7 ✅
- Expected hash values (proof hash, mandatory hash) ✅
- Placeholder tests for base/derived proof creation/verification

## W3C Conformance

### Implemented Features

✅ **Base Proof Creation** (Section 3.6.5)
- ECDSA signature over canonicalized credential
- HMAC key generation for blank node randomization
- Proof configuration canonicalization
- CBOR encoding with multibase serialization

✅ **Derived Proof Creation** (Section 3.6.6)
- Selective field disclosure
- Mandatory field enforcement
- Blank node re-randomization
- Compressed label map generation
- Statement index calculation

✅ **Verification** (Section 3.7)
- Base proof signature verification
- Derived proof validation
- Mandatory pointer checking
- RDF canonicalization (URDNA2015)

✅ **Key Encoding**
- Multikey format for public keys
- Compressed and uncompressed representations
- P-256 and P-384 curve support

### Pending Items

⏳ **Complete W3C Test Vectors**
- Need full test vectors from spec Appendix A.7/A.8
- Infrastructure ready for implementation
- Will validate against reference implementation

⏳ **Challenge/Domain in Proof Objects**
- Currently included in proof configuration
- May need to add to DataIntegrityProof struct
- Awaiting final spec clarification

## Known Limitations

1. **Blank Node Pointer Support**: Currently uses simple string matching for blank node identification. More sophisticated JSON-LD blank node handling may be needed for complex credentials.

2. **Performance**: Canonicalization can be expensive for large credentials. Consider caching canonical forms for repeated operations.

3. **Curve Support**: Limited to P-256 and P-384. secp256k1 support may be added in future.

## Usage Examples

### Creating a Base Proof

```go
suite := ecdsasd.NewSuite()
privateKey, _ := suite.GenerateKeyPair()

credential := &credential.VerifiableCredential{
    Context: []string{"https://www.w3.org/ns/credentials/v2"},
    Type:    []string{"VerifiableCredential"},
    Issuer:  "https://example.com/issuers/123",
    CredentialSubject: map[string]interface{}{
        "id":   "did:example:subject",
        "name": "Alice",
        "age":  30,
    },
}

options := ecdsasd.BaseProofOptions{
    VerificationMethod: "https://example.com/issuers/123#key-1",
    ProofPurpose:       "assertionMethod",
    MandatoryPointers:  []string{"/credentialSubject/id"},
}

proof, err := suite.CreateBaseProof(credential, privateKey, options)
```

### Creating a Derived Proof

```go
// Holder selects which fields to reveal
derivedOptions := ecdsasd.DerivedProofOptions{
    VerificationMethod: "did:example:holder#key-1",
    SelectivePointers:  []string{"/credentialSubject/name"}, // Reveal name
    // credentialSubject/id automatically included (mandatory)
    // age will be hidden
}

derivedProof, disclosedCred, err := suite.CreateDerivedProof(
    credential,
    baseProof,
    derivedOptions,
)
```

### Verifying Proofs

```go
// Verify base proof
valid, err := suite.VerifyBaseProof(credential, baseProof)

// Verify derived proof
valid, err := suite.VerifyDerivedProof(disclosedCred, derivedProof, baseProof)
```

## Security Considerations

1. **HMAC Key Protection**: The HMAC key in base proofs enables blank node randomization. Keep base proofs secure to prevent correlation attacks.

2. **Mandatory Field Enforcement**: Mandatory pointers are enforced at derived proof creation time. Verifiers must check that mandatory fields are present.

3. **Signature Algorithm**: Uses ECDSA with SHA-256 (P-256) or SHA-384 (P-384). Ensure proper key management and rotation policies.

4. **Canonicalization**: Relies on URDNA2015 for deterministic serialization. Ensure consistent JSON-LD context handling.

## References

- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity ECDSA Cryptosuites](https://www.w3.org/TR/vc-di-ecdsa/)
- [RDF Dataset Canonicalization (URDNA2015)](https://www.w3.org/TR/rdf-canon/)
- [Multikey Specification](https://w3c.github.io/controller-document/)

## Contributing

When adding new features:
1. Add comprehensive tests (happy path + edge cases)
2. Update this documentation
3. Ensure W3C spec compliance
4. Run full test suite: `go test -tags vc20 ./pkg/vc20/...`

## License

See LICENSE.md in repository root.

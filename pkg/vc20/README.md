# W3C Verifiable Credentials 2.0 with JSON-LD and ECDSA-SD-2023

This package implements support for W3C Verifiable Credentials Data Model v2.0 with JSON-LD credentials and the ECDSA-SD-2023 selective disclosure cryptosuite.

## Status: 🚧 Work in Progress

**Phase 1 Foundation: ✅ COMPLETED**
- ✅ W3C VC 2.0 data structures (`pkg/vc20/credential`)
- ✅ Context management and validation (`pkg/vc20/contextstore`)
- ✅ Core dependencies integrated

**Phase 2 RDF Canonicalization: ✅ COMPLETED**
- ✅ RDFC-1.0 implementation (`pkg/vc20/rdfcanon`)
- ✅ URDNA2015 algorithm via json-gold
- ✅ Dataset and N-Quads handling
- ✅ All tests passing (11 test functions)

**Phase 3 ECDSA-SD-2023 Cryptosuite: 📝 TODO**
- ⏳ Base proof creation (issuer)
- ⏳ Derived proof creation (holder)
- ⏳ Derived proof verification (verifier)

**Phase 4 Integration: 📝 TODO**
- ⏳ W3C test suite integration
- ⏳ Service integration
- ⏳ Documentation

## Building

This package uses a build tag to make it optional:

```bash
# Build with VC 2.0 support
go build -tags=vc20 ./...

# Run tests
go test -tags=vc20 ./pkg/vc20/...
```

## Package Structure

```
pkg/vc20/
├── credential/          # VC 2.0 data model
│   ├── credential.go   # JSON-LD credential structures
│   ├── errors.go       # Error definitions
│   └── *_test.go       # Tests
├── contextstore/       # Context management
│   ├── manager.go      # Context caching and validation
│   └── *_test.go       # Tests
├── rdfcanon/           # RDF Canonicalization (RDFC-1.0)
│   ├── canonicalize.go # URDNA2015 implementation
│   └── *_test.go       # Tests
└── crypto/             # Cryptographic suites (TODO)
    ├── ecdsa-sd/       # ECDSA-SD-2023 cryptosuite
    └── keys/           # Key management
```

## Features Implemented

### Credential Data Model (`pkg/vc20/credential`)

- **VerifiableCredential** - Complete W3C VC 2.0 data model
  - JSON-LD `@context` support
  - Required fields: `type`, `issuer`, `validFrom`, `credentialSubject`
  - Optional fields: `id`, `validUntil`, `credentialStatus`, `credentialSchema`, etc.
  - Data Integrity proof structures
  
- **Validation**
  - Base context URL validation (`https://www.w3.org/ns/credentials/v2`)
  - Required field validation
  - Type checking
  - Temporal validity checking (`validFrom`, `validUntil`)
  - Issuer ID extraction (string or object format)

- **Utility Functions**
  - JSON marshaling/unmarshaling
  - Time parsing (RFC3339)
  - Expiration checking
  - Current validity checking

### Context Management (`pkg/vc20/contextstore`)

- **Context Manager** - HTTP-based context document fetching and caching
  - Thread-safe caching with TTL
  - SHA-256 hash computation for context documents
  - Base context hash verification (integrity checking)
  - Preloading support for offline/testing scenarios
  - Automatic expiration and cache cleanup

- **Validation**
  - Base context URL and hash verification
  - Multi-context validation
  - HTTP fetching with timeouts

### RDF Canonicalization (`pkg/vc20/rdfcanon`)

- **Canonicalizer** - RDFC-1.0 (URDNA2015) implementation
  - JSON-LD to canonical N-Quads conversion
  - SHA-256 hashing of canonicalized output
  - Deterministic RDF graph serialization
  - Uses json-gold library (92.3% W3C conformance)

- **Dataset** - RDF quad management
  - N-Quads format parsing
  - Quad sorting and hashing
  - Graph filtering and extraction
  - Dataset conversion to/from N-Quads

- **Operations**
  - `Canonicalize(doc)` - Convert JSON-LD to canonical N-Quads
  - `Hash(doc)` - Compute SHA-256 hash of canonicalized form
  - `ParseNQuads(nquads)` - Parse N-Quads into Dataset
  - `Dataset.Sort()` - Canonical quad ordering
  - `Dataset.FilterByGraph(graph)` - Extract specific graph

## Constants

### Context URLs
- `VC20ContextURL` - `https://www.w3.org/ns/credentials/v2`
- `VC20ContextHash` - SHA-256 hash: `59955ced6697d61e03f2b2556febe5308ab16842846f5b586d7f1f7adec92734`

### Media Types
- `MediaTypeVC` - `application/vc`
- `MediaTypeVP` - `application/vp`

### Proof Types
- `ProofTypeDataIntegrity` - `DataIntegrityProof`
- `CryptosuiteECDSASD2023` - `ecdsa-sd-2023` (implementation pending)
- `CryptosuiteECDSARDFC2019` - `ecdsa-rdfc-2019` (planned)
- `CryptosuiteECDSAJCS2019` - `ecdsa-jcs-2019` (planned)

## Example Usage

```go
// +build vc20

package main

import (
    "fmt"
    "time"
    
    "vc/pkg/vc20/credential"
    "vc/pkg/vc20/contextstore"
)

func main() {
    // Create a credential
    vc := &credential.VerifiableCredential{
        Context:   []string{credential.VC20ContextURL},
        Type:      []string{credential.TypeVerifiableCredential, "UniversityDegree"},
        Issuer:    "did:example:university",
        ValidFrom: time.Now().Format(time.RFC3339),
        CredentialSubject: map[string]any{
            "id":     "did:example:student",
            "degree": "Bachelor of Science",
            "major":  "Computer Science",
        },
    }
    
    // Validate the credential
    if err := vc.Validate(); err != nil {
        panic(err)
    }
    
    // Create context manager
    ctxMgr := contextstore.NewManager()
    
    // Validate contexts (requires network access)
    if err := ctxMgr.ValidateContexts(vc.Context); err != nil {
        fmt.Printf("Context validation failed: %v\n", err)
    }
    
    // Check if credential is valid now
    if vc.IsValidNow() {
        fmt.Println("Credential is currently valid")
    }
    
    // Marshal to JSON
    data, _ := vc.ToJSON()
    fmt.Println(string(data))
}
```

## Dependencies

### External Libraries
- `github.com/piprate/json-gold` v0.7.0 - JSON-LD 1.1 processing
- `github.com/fxamacker/cbor/v2` v2.6.0 - CBOR encoding
- `github.com/multiformats/go-multibase` v0.2.0 - Multibase encoding
- `github.com/cloudflare/circl` v1.3.7 - ECDSA P-256/P-384

### Standard Library
- `crypto/sha256` - Context hash verification
- `crypto/ecdsa` - ECDSA operations (planned)
- `crypto/hmac` - HMAC for blank nodes (planned)
- `encoding/json` - JSON processing
- `net/http` - Context fetching

## Specifications

- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [Data Integrity ECDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-ecdsa/)
- [RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/)
- [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/)

## Next Steps

The next phases of implementation will focus on:

1. **RDF Canonicalization (RDFC-1.0)**
   - Implement the canonical ordering algorithm
   - Use json-gold for RDF dataset generation
   - Hash computation for RDF statements

2. **ECDSA-SD-2023 Cryptosuite**
   - Base proof creation with HMAC blank node randomization
   - Derived proof creation with JSON Pointer selection
   - Signature verification
   - CBOR serialization for proof values
   - Multikey encoding for public keys

3. **Integration**
   - W3C test vectors (Appendix A.7, A.8)
   - Service integration (issuer, verifier)
   - Complete documentation

## Testing

All packages include comprehensive unit tests:

```bash
# Run all vc20 tests
go test -tags=vc20 -v ./pkg/vc20/...

# Run specific package tests
go test -tags=vc20 -v ./pkg/vc20/credential/
go test -tags=vc20 -v ./pkg/vc20/contextstore/

# Run with coverage
go test -tags=vc20 -cover ./pkg/vc20/...
```

## Contributing

This is an active development project. The implementation follows the W3C specifications closely and aims for full compliance with test vectors.

## License

[Your project's license]

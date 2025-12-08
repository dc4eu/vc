# Development Roadmap

This document outlines planned features and improvements for the VC issuer/verifier system.

## Priority 1: VCTM Schema Validation ✅ COMPLETED

**Status**: Implemented in branch `feat/vctm-schema-validation`

Add comprehensive VCTM schema validation to prevent invalid credentials from being issued.

- Validate document data against VCTM schema before credential issuance
- Check mandatory claims presence and structure
- Support nested claim paths and array values
- Provide detailed field-level error messages
- Auto-allow standard JWT claims
- Support strict/non-strict validation modes

**Benefits**: Prevents malformed credentials from being signed, provides better error messages to API clients.

## Priority 2: Enhanced Error Messages for API Clients

Improve error message quality and structure for better developer experience.

- Standardize error response format across all endpoints
- Include error codes and categories (validation, authentication, authorization, etc.)
- Add detailed context and suggestions for resolution
- Provide JSON Schema validation errors where applicable
- Build on the validation framework from Priority 1

**Benefits**: Faster integration for API clients, reduced support burden, better debugging.

## Priority 3: Configuration Management Improvements

Enhance configuration flexibility and operational convenience.

- Support hot-reload of VCTM files without service restart
- Add configuration validation on startup with detailed error reporting
- Support environment-specific configuration overrides
- Add configuration versioning and change tracking
- Implement configuration validation endpoint for pre-deployment checks
- Improve error messages for configuration issues
- Add admin endpoint to refresh configuration without restart

**Benefits**: Faster deployments, reduced downtime, better developer experience, easier troubleshooting.

## Priority 4: Batch Credential Issuance

Add support for issuing multiple credentials in a single API request.

- Design batch issuance API endpoint
- Support parallel credential generation
- Implement atomic batch operations (all-or-nothing)
- Add batch size limits and rate limiting
- Provide detailed batch status reporting (success/failed per credential)

**Benefits**: Improved efficiency for bulk issuance scenarios, reduced API overhead.

## Priority 5: Revocation Status Integration

Integrate credential revocation status checking and management.

- Implement status list support (StatusList2021 or equivalent)
- Add revocation endpoints to issuer API
- Integrate status checking in verifier
- Support suspension and reactivation
- Add audit trail for status changes

**Benefits**: Complete credential lifecycle management, compliance with revocation requirements.

## Priority 6: Performance Benchmarking

Establish performance baselines and monitoring.

- Create benchmark suite for credential issuance
- Benchmark verification performance
- Profile cryptographic operations (signing, SD-JWT creation)
- Identify and optimize bottlenecks
- Establish SLA targets and alerts

**Benefits**: Performance confidence for production deployment, optimization guidance.

## Priority 7: Documentation Updates

Comprehensive documentation for the generic credential builder and new features.

- Update API documentation for generic credential builder
- Document VCTM schema structure and validation rules
- Add integration guides with examples
- Document SAML integration configuration
- Create troubleshooting guides
- Add sequence diagrams for key flows

**Benefits**: Easier onboarding, reduced support questions, better adoption.

## Priority 8: Integration Test Expansion

Expand integration test coverage for production confidence.

- Add end-to-end tests for complete issuance flows
- Test OpenID4VCI flows with real wallet simulation
- Add verifier integration tests with presentation exchange
- Test SAML integration scenarios
- Add negative test cases and edge conditions
- Performance/load testing scenarios

**Benefits**: Higher confidence in releases, catch integration issues early.

## Priority 9: Production Monitoring Setup

Establish production observability and monitoring.

- Define key metrics (issuance rate, error rates, latency percentiles)
- Set up dashboards for operational visibility
- Configure alerts for anomalies and errors
- Implement distributed tracing for request flows
- Add structured logging with correlation IDs
- Create runbooks for common operational scenarios

**Benefits**: Operational excellence, faster incident response, proactive issue detection.

## Priority 10: W3C Digital Credentials API Support in Verifier ✅ COMPLETED

**Status**: Implemented in PR #218, merged to main

Implemented support for the W3C Digital Credentials API in the verifier component.

- ✅ Implemented Digital Credentials API endpoints
- ✅ Support credential request/response protocol
- ✅ Added browser-based credential presentation flow
- ✅ Integrated with existing presentation exchange logic
- ✅ Support credential selection UI with enhanced authorization page
- ✅ Added comprehensive testing for browser flows
- ✅ Created documentation: `docs/DIGITAL_CREDENTIALS_API.md`
- ✅ Added example configuration: `config.digital-credentials-example.yaml`

**Key Features Delivered**:
- Digital Credentials JavaScript API implementation (`digital-credentials.js`)
- Enhanced authorization page with session preferences (`authorize_enhanced.html`)
- Credential display UI (`credential_display.html`)
- Session preference management for protocol selection
- Full integration with OpenID4VP flow

**Benefits**: Enabled browser-based credential verification, aligned with W3C standards, improved user experience for web-based verifiers.

**References**:
- [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/)
- Related to OpenID4VP browser flows
- Documentation: `docs/DIGITAL_CREDENTIALS_API.md`

## Priority 11: OpenID Connect Relying Party for Credential Issuance ✅ COMPLETED

**Status**: Implemented in PR #217, merged to main

Implemented OIDC Relying Party (RP) functionality to issue credentials based on OpenID Connect authentication flows, analogous to the existing SAML Service Provider integration.

### Implementation Summary

**1. Configuration Structure** (`pkg/model/config.go`):
- ✅ Added `OIDCRPConfig` with support for multiple OIDC providers
- ✅ Implemented credential mappings reusing existing `CredentialMapping` structure
- ✅ Support for both OIDC Discovery and static configuration
- ✅ Session duration and security settings

**2. OIDC RP Service** (`pkg/oidcrp/`):
- ✅ `service.go` - Core OIDC RP implementation
- ✅ `session.go` - Session management using ttlcache
- ✅ `transformer.go` - Claim transformation from OIDC to credentials
- ✅ `cache.go` - OIDC Provider metadata caching
- ✅ `dynamic_registration.go` - Dynamic Client Registration support
- ✅ OIDC Provider discovery (`.well-known/openid-configuration`)
- ✅ OAuth2 authorization code flow with PKCE
- ✅ ID token verification and claim extraction
- ✅ Comprehensive test coverage

**3. API Endpoints** (`internal/apigw/`):
- ✅ `POST /oidcrp/initiate` - Start OIDC authentication
- ✅ `GET /oidcrp/callback` - Handle OIDC provider callback
- ✅ Layered architecture: httpserver → apiv1 → pkg
- ✅ Build tag support for optional compilation (`-tags=oidcrp`)

**4. Authentication Flow**:
1. ✅ Client calls `/oidcrp/initiate` with credential_type
2. ✅ Service generates OAuth2 authorization URL with PKCE
3. ✅ User authenticates at OIDC Provider
4. ✅ Provider redirects to `/oidcrp/callback` with authorization code
5. ✅ Service exchanges code for tokens, verifies ID token
6. ✅ Claims extracted from ID token
7. ✅ Claims transformed using `ClaimTransformer`
8. ✅ Credential issued via issuer gRPC
9. ✅ Credential + offer returned to client

### Key Features Delivered

**Reusable Components**:
- ✅ Protocol-agnostic `ClaimTransformer` (shared with SAML)
- ✅ Unified `CredentialMapping` configuration
- ✅ Build tag architecture for optional features

**OIDC-Specific**:
- ✅ OIDC Provider discovery and metadata caching
- ✅ OAuth2 code flow with PKCE implementation
- ✅ JWT/JWK verification using `github.com/coreos/go-oidc/v3`
- ✅ Session store with automatic TTL cleanup (ttlcache)
- ✅ Dynamic Client Registration (RFC 7591) support

**Architecture Improvements**:
- ✅ Moved business logic to apiv1 layer (addresses code review)
- ✅ Thin httpserver endpoints (improved separation of concerns)
- ✅ Interface-based dependency injection
- ✅ Stub implementations for non-OIDC builds

**Documentation**:
- ✅ Comprehensive documentation: `docs/OIDC_RP.md`
- ✅ Configuration examples
- ✅ Integration guide

### Dependencies Added

- `github.com/coreos/go-oidc/v3/oidc` - Provider discovery, token verification
- `golang.org/x/oauth2` - OAuth2 flows
- `github.com/jellydator/ttlcache/v3` - Session management

### Benefits Realized

- **Broader Compatibility**: Support for Google, Microsoft, Keycloak, Auth0, etc.
- **Modern Protocol**: Industry-standard OAuth2/OIDC flows
- **Reusable Architecture**: Shares claim transformation with SAML
- **Flexible Deployment**: Discovery or static configuration
- **Secure**: PKCE, nonce, standard JWT verification
- **Optional Build**: Compile-time flag (`-tags=oidcrp`)
- **Production Ready**: Comprehensive tests, documentation, proper layering

**References**:
- Documentation: `docs/OIDC_RP.md`
- RFC 6749 (OAuth 2.0)
- OpenID Connect Core 1.0
- RFC 7591 (Dynamic Client Registration)

---

## Priority 12: W3C Verifiable Credentials 2.0 with JSON-LD and ECDSA-SD-2023 🚧 IN PROGRESS

**Status**: Implementation started - November 2025

Add support for W3C Verifiable Credentials Data Model 2.0 with JSON-LD credentials and ECDSA-SD-2023 selective disclosure cryptosuite.

### Implementation Plan

**Phase 1: Foundation Libraries and Data Structures** (Weeks 1-2):
- ✅ Add Go dependencies (json-gold, CBOR, multibase)
- ✅ Implement W3C VC 2.0 data model in `pkg/vc20/credential`
  - JSON-LD credential structures with `@context`, `type`, `issuer`, `validFrom`, `credentialSubject`
  - Media type support (`application/vc`, `application/vp`)
  - Context validation with SHA-256 hash verification
- ✅ Implement context manager in `pkg/vc20/context`
  - Context document caching
  - Cryptographic hash validation for base context
  - Support for `https://www.w3.org/ns/credentials/v2`

**Phase 2: RDF Canonicalization** (Weeks 3-4): ✅ COMPLETED
- ✅ Implement RDFC-1.0 (RDF Dataset Canonicalization) in `pkg/vc20/rdfcanon`
  - RDF dataset generation using json-gold
  - URDNA2015 canonicalization algorithm
  - Hash algorithms (SHA-256)
  - Dataset and Quad structures for RDF manipulation
  - N-Quads parsing and serialization
  - All tests passing (11 test functions)

**Phase 3: ECDSA-SD-2023 Cryptosuite** (Weeks 5-7):
- 🚧 Implement base proof creation (issuer) in `pkg/vc20/crypto/ecdsa-sd`
  - HMAC-based blank node randomization (256-bit keys)
  - RDF transformation and hashing
  - P-256 ECDSA signing (P-384 optional)
  - CBOR serialization for proof values
  - Multibase encoding with specific headers
- 🚧 Implement derived proof creation (holder)
  - JSON Pointer-based selective disclosure
  - Mandatory vs non-mandatory statement handling
  - Derived proof CBOR structure
- 🚧 Implement derived proof verification (verifier)
  - Signature verification
  - Selective disclosure validation
  - Security checks per W3C spec

**Phase 4: Integration and Testing** (Weeks 8-10):
- 🚧 W3C Official Test Suite Integration
  - Implement VC-API compatible endpoints (`/credentials/issue`, `/credentials/verify`, `/presentations/verify`)
  - Run against official W3C VC Data Model 2.0 Test Suite (https://github.com/w3c/vc-data-model-2.0-test-suite)
  - Support `eddsa-rdfc-2022` cryptosuite for initial interoperability
  - Support `ecdsa-sd-2023` cryptosuite for selective disclosure
  - Register implementation in w3c/vc-test-suite-implementations
- 🚧 Specification Test Vectors
  - ECDSA-SD-2023 Appendix A.7 and A.8 test cases
  - RDF Canonicalization test vectors
  - Cross-implementation interoperability validation
- 🚧 Service Integration
  - Issuer service support for JSON-LD credentials
  - Verifier service support for ECDSA-SD-2023
  - Build tag support (`-tags=vc20`)
- 🚧 Documentation
  - `docs/VC20_JSON_LD.md` - Usage guide
  - VC-API endpoint implementation guide
  - W3C test suite integration guide
  - API examples and integration patterns
  - Security considerations

### Technical Architecture

```
pkg/vc20/
├── credential/          # VC 2.0 data model
│   ├── credential.go   # JSON-LD credential structures
│   ├── builder.go      # Credential builder
│   ├── parser.go       # Parse JSON-LD credentials
│   └── validator.go    # Basic validation
├── context/            # Context management
│   ├── manager.go      # Context document handling
│   ├── cache.go        # Context caching
│   └── validator.go    # Hash verification
├── crypto/
│   ├── ecdsa-sd/       # ECDSA-SD-2023 cryptosuite
│   │   ├── suite.go    # Cryptosuite interface
│   │   ├── base_proof.go     # Base proof creation
│   │   ├── derived_proof.go  # Derived proof creation/verify
│   │   ├── hmac.go           # HMAC randomization
│   │   ├── selection.go      # JSON Pointer selection
│   │   └── cbor.go           # CBOR serialization
│   └── keys/
│       ├── multikey.go # Multikey encoding/decoding
│       └── ecdsa.go    # ECDSA key helpers
└── rdfcanon/           # RDF Canonicalization
    ├── canonicalize.go # RDFC-1.0 implementation
    ├── dataset.go      # RDF dataset handling
    └── hash.go         # Hash algorithms
```

### Key Dependencies

**External Libraries**:
- `github.com/piprate/json-gold` v0.7.0 - JSON-LD 1.1 processing, RDF dataset generation
- `github.com/fxamacker/cbor/v2` - CBOR encoding for proof values
- `github.com/multiformats/go-multibase` - Multibase encoding
- `github.com/cloudflare/circl` - P-256/P-384 ECDSA cryptography
- Standard library: `crypto/ecdsa`, `crypto/hmac`, `crypto/sha256`

**Specifications Implemented**:
- [W3C Verifiable Credentials Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [Data Integrity ECDSA Cryptosuites v1.0](https://www.w3.org/TR/vc-di-ecdsa/)
- [RDF Dataset Canonicalization (RDFC-1.0)](https://www.w3.org/TR/rdf-canon/)
- [JSON-LD 1.1](https://www.w3.org/TR/json-ld11/)

### Implementation Challenges

1. **RDF Canonicalization (RDFC-1.0)** - Most complex component
   - No existing Go implementation available
   - Must implement algorithm from specification
   - Critical for cryptographic security
   - Heavy dependency on json-gold

2. **ECDSA-SD-2023 Selective Disclosure** - Novel cryptographic scheme
   - HMAC-based blank node randomization
   - JSON Pointer selection mechanisms
   - Mandatory pointer handling
   - CBOR proof serialization

3. **Interoperability** - Must pass W3C test vectors
   - Test vectors in specification appendices
   - Cross-platform compatibility verification

### Benefits

- **W3C Standards Compliance**: Support for latest VC 2.0 specification
- **Selective Disclosure**: Privacy-preserving credential presentation with ECDSA-SD-2023
- **JSON-LD Support**: Semantic interoperability and extensibility
- **Cryptographic Agility**: Multiple curve support (P-256, P-384)
- **Future-Proof**: Aligned with W3C's direction for verifiable credentials

### Build Tag Support

Following existing pattern for optional features:

```go
//go:build vc20

package vc20
```

Compile with: `go build -tags=vc20`

---

## Timeline and Sequencing

**Phase 1 - Foundation** (Priorities 1-3):
- Core quality improvements
- Better error handling and configuration management

**Phase 2 - Feature Expansion** (Priorities 4-5, 10-11, 12):
- Batch operations and lifecycle management
- New authentication and presentation protocols
- W3C VC 2.0 JSON-LD with ECDSA-SD-2023

**Phase 3 - Production Readiness** (Priorities 6-9):
- Performance validation
- Documentation and testing
- Operational excellence

## Notes

- Priorities may be reordered based on stakeholder needs
- Some priorities can be worked on in parallel
- Each priority should include comprehensive tests
- Consider backward compatibility for all changes

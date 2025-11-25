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

## Priority 10: W3C Digital Credentials API Support in Verifier

Implement support for the W3C Digital Credentials API in the verifier component.

- Implement Digital Credentials API endpoints
- Support credential request/response protocol
- Add browser-based credential presentation flow
- Integrate with existing presentation exchange logic
- Support credential selection UI
- Add comprehensive testing for browser flows

**Benefits**: Enable browser-based credential verification, align with W3C standards, improve user experience for web-based verifiers.

**References**:
- [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/)
- Related to OpenID4VP browser flows

## Priority 11: OpenID Connect Relying Party for Credential Issuance

Implement OIDC Relying Party (RP) functionality to issue credentials based on OpenID Connect authentication flows, analogous to the existing SAML Service Provider integration.

### Architecture Overview

The implementation will add OIDC RP capabilities in `pkg/oidcrp/` and `internal/apigw/httpserver/`, following the same patterns established by the SAML integration. This allows issuing credentials based on authentication against external OIDC Providers (Google, Azure AD, Keycloak, etc.).

### Key Components

**1. Configuration Structure** (`pkg/model/config.go`):
```yaml
apigw:
  oidcrp:
    enabled: true
    client_id: "my-client-id"
    client_secret: "my-client-secret"
    redirect_uri: "https://issuer.example.com/oidcrp/callback"
    issuer_url: "https://accounts.google.com"  # For OIDC Discovery
    scopes: ["openid", "profile", "email"]
    session_duration: 3600
    
    # Reuse existing CredentialMapping structure (protocol-agnostic)
    credential_mappings:
      pid:
        credential_config_id: "urn:eudi:pid:1"
        attributes:
          sub: {claim: "identity.unique_id", required: true}
          given_name: {claim: "identity.given_name", required: true}
          family_name: {claim: "identity.family_name", required: true}
          email: {claim: "identity.email", required: false}
```

**2. OIDC RP Service** (`pkg/oidcrp/service.go`):
- OIDC Provider discovery (`.well-known/openid-configuration`)
- OAuth2 authorization code flow with PKCE
- ID token verification and claim extraction
- Session management (state, nonce, code_verifier)
- UserInfo endpoint support for additional claims

**3. API Endpoints** (`internal/apigw/httpserver/`):
- `POST /oidcrp/initiate` - Start OIDC authentication
- `GET /oidcrp/callback` - Handle OIDC provider callback

**4. Authentication Flow**:
1. Client calls `/oidcrp/initiate` with credential_type
2. Service generates OAuth2 authorization URL with PKCE
3. User authenticates at OIDC Provider
4. Provider redirects to `/oidcrp/callback` with authorization code
5. Service exchanges code for tokens, verifies ID token
6. Claims extracted from ID token (+ UserInfo if needed)
7. Claims transformed using existing `ClaimTransformer` (protocol-agnostic)
8. Credential issued via issuer gRPC
9. Credential + offer returned to client

### Reusable Components

**Already Protocol-Agnostic** (shared with SAML):
- ✅ `AttributeConfig` - Claim mapping configuration
- ✅ `CredentialMapping` - Credential type configuration
- ✅ `ClaimTransformer` - Claim transformation logic (supports dot-notation paths, transforms, defaults)

**OIDC-Specific** (new):
- OIDC Provider discovery and metadata caching
- OAuth2 code flow with PKCE implementation
- JWT/JWK verification using standard libraries
- Session store for OAuth2 state/nonce

### Implementation Phases

**Phase 1 - Core OIDC RP**:
- `pkg/oidcrp/` package structure
- Service initialization with OIDC Discovery
- Session management (state, nonce, PKCE)
- Authorization code flow implementation
- APIGW route registration with build tags

**Phase 2 - Claim Transformation**:
- Reuse `pkg/saml/transformer.go` (already supports OIDC claims)
- Configuration-driven mappings
- Support UserInfo endpoint for extended claims
- Handle nested claim paths

**Phase 3 - Credential Issuance**:
- Integration with issuer gRPC service
- Credential offer generation (OpenID4VCI)
- Error handling and validation
- Session cleanup

**Phase 4 - Production Features**:
- Multiple OIDC Provider support
- Dynamic Client Registration (RFC 7591) support
- Comprehensive testing with real providers
- Documentation and examples

### Dependencies

Standard Go libraries for OIDC:
- `github.com/coreos/go-oidc/v3/oidc` - Provider discovery, token verification
- `golang.org/x/oauth2` - OAuth2 flows

### Key Differences from SAML

| Aspect | SAML | OIDC RP |
|--------|------|---------|
| Metadata | XML (SP/IdP metadata) | JSON (OIDC Discovery) |
| Cryptography | X.509 certificates | JWK, JWT signatures |
| Protocol Flow | SAML AuthnRequest → Assertion | OAuth2 code flow → ID Token |
| Attributes | SAML Attributes (OIDs) | OIDC Claims (JSON) |
| Session Security | RelayState | OAuth2 state + nonce + PKCE |
| Provider Discovery | MDQ or static metadata | `.well-known/openid-configuration` |

### Benefits

- **Broader Compatibility**: Support Google, Microsoft, Keycloak, Auth0, etc.
- **Modern Protocol**: Industry-standard OAuth2/OIDC flows
- **Reusable Architecture**: Shares claim transformation with SAML
- **Flexible Deployment**: Discovery or static configuration
- **Secure**: PKCE, nonce, standard JWT verification
- **Optional Build**: Compile-time flag like SAML (`-tags=oidcrp`)

### Design Considerations

- Reuse `ClaimTransformer` from SAML (already protocol-agnostic)
- Follow same configuration patterns as `SAMLConfig`
- Use build tags for optional compilation
- Mirror endpoint structure (`endpoints_saml.go` → `endpoints_oidcrp.go`)
- Support both OIDC Discovery and static provider configuration
- Implement standard OAuth2 security (PKCE, state, nonce)

---

## Timeline and Sequencing

**Phase 1 - Foundation** (Priorities 1-3):
- Core quality improvements
- Better error handling and configuration management

**Phase 2 - Feature Expansion** (Priorities 4-5, 10-11):
- Batch operations and lifecycle management
- New authentication and presentation protocols

**Phase 3 - Production Readiness** (Priorities 6-9):
- Performance validation
- Documentation and testing
- Operational excellence

## Notes

- Priorities may be reordered based on stakeholder needs
- Some priorities can be worked on in parallel
- Each priority should include comprehensive tests
- Consider backward compatibility for all changes

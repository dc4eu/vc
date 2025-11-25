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

## Priority 3: VCTM Caching Optimization

Optimize VCTM retrieval and caching for improved performance.

- Implement in-memory cache for VCTM metadata
- Add cache invalidation strategies (TTL, manual refresh)
- Support cache warming on startup
- Add metrics for cache hit/miss rates
- Consider distributed cache for multi-instance deployments

**Benefits**: Reduced latency for credential issuance, lower load on metadata storage.

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

## Priority 11: OpenID Authentication Flow for Credential Issuance

Implement support for issuing credentials based on OpenID Connect authentication flows, analogous to the existing SAML authentication integration.

- Design OpenID Connect integration architecture
- Implement OIDC authentication handler
- Create claim transformation mappings (similar to SAML ClaimTransformer)
- Support standard OIDC claims mapping to VCTM
- Add YAML-based configuration for OIDC providers
- Support multiple OIDC identity providers
- Implement session management and callback handling
- Add comprehensive testing including mock OIDC provider

**Benefits**: Broader identity provider compatibility, modern authentication protocol support, flexibility for different deployment scenarios.

**Design Considerations**:
- Reuse patterns from existing SAML integration
- Protocol-agnostic claim transformation layer
- Configuration-driven provider setup
- Similar to `endpoints_saml.go` but for OIDC

---

## Timeline and Sequencing

**Phase 1 - Foundation** (Priorities 1-3):
- Core quality and performance improvements
- Better error handling and caching

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

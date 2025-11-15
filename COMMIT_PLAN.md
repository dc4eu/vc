# Commit Plan & PR Strategy

## Overview
This document outlines the commit strategy for the verifier proxy integration test suite and production bug fixes discovered during testing.

---

## Commit Series 1: Integration Test Infrastructure (Foundation)

### Commit 1: Add integration test infrastructure and test suite
**Files:**
- `internal/verifier_proxy/integration/suite.go` (new)
- `internal/verifier_proxy/integration/helpers.go` (new)
- `internal/verifier_proxy/apiv1/testing.go` (new)
- `internal/verifier_proxy/integration/STATUS.md` (new)

**Message:**
```
feat(verifier-proxy): Add integration test infrastructure

Implements comprehensive integration test suite using testcontainers:

- IntegrationSuite with real MongoDB in Docker containers
- Automatic container lifecycle management (startup/cleanup)
- Helper functions for PKCE, JWT, wallet simulation
- Test client registration and bootstrapping
- Support for direct API testing (no HTTP layer)

Infrastructure features:
- Testcontainers-go for MongoDB 7
- Automatic port mapping
- Test configuration with configurable durations
- RSA key generation for JWT signing
- SetSigningKeyForTesting() helper for apiv1 testing

Preparation for comprehensive OIDC + OpenID4VP flow testing.
```

### Commit 2: Add integration test scenarios
**Files:**
- `internal/verifier_proxy/integration/flows_test.go` (new)

**Message:**
```
test(verifier-proxy): Add integration test scenarios

Implements 5 comprehensive integration test scenarios:

1. TestIntegration_BasicAuthorizationFlow - Full OIDC + OpenID4VP flow
   - Authorization request → QR code → VP submission → token exchange → userinfo

2. TestIntegration_PKCEValidation - PKCE security (3 subtests)
   - Missing code challenge rejection
   - Wrong verifier rejection  
   - Correct verifier acceptance

3. TestIntegration_CodeReplayPrevention - Code reuse protection
   - First code exchange succeeds
   - Second attempt rejected

4. TestIntegration_SessionExpiration - Configurable timeouts
   - Session valid within TTL
   - Session rejected after expiration

5. TestIntegration_InvalidClient - Error handling (3 subtests)
   - Non-existent client rejection
   - Invalid redirect URI rejection
   - Wrong client secret rejection

Tests use real MongoDB via testcontainers, no mocks.
Runtime: ~8 seconds for full suite.

Related: #<issue-number>
```

---

## Commit Series 2: Production Bug Fixes (Critical)

### Commit 3: Fix authorization code replay vulnerability
**Files:**
- `internal/verifier_proxy/apiv1/handler_oidc.go` (modified)

**Message:**
```
fix(verifier-proxy): Prevent authorization code replay attacks

SECURITY FIX: Authorization codes could be reused multiple times,
violating OAuth 2.0 security requirements (RFC 6749 Section 10.5).

Root Cause:
Race condition between MarkCodeAsUsed() and Update():
1. MarkCodeAsUsed() sets authorization_code_used=true in MongoDB
2. Update() immediately saves in-memory session (still false)
3. Database flag overwritten back to false

Fix:
Synchronize in-memory session after MarkCodeAsUsed() call:

  session.Tokens.AuthorizationCodeUsed = true

This prevents Update() from overwriting the database flag.

Discovered by: Integration test TestIntegration_CodeReplayPrevention
Severity: HIGH (security vulnerability)

Related: #<issue-number>
```

### Commit 4: Make session/token durations configurable
**Files:**
- `internal/verifier_proxy/apiv1/handler_oidc.go` (modified)
- `internal/verifier_proxy/apiv1/handler_api.go` (modified)

**Message:**
```
fix(verifier-proxy): Use configured durations for sessions and tokens

Replaces hardcoded time durations with configuration values:

Before:
- Session expiration: 15 minutes (hardcoded)
- Code expiration: 5 minutes (hardcoded)
- Access token: 1 hour (hardcoded)
- Refresh token: 30 days (hardcoded)

After:
- All durations use cfg.VerifierProxy.OIDC.*Duration values
- Configurable per deployment
- Testable with short durations (2 seconds)

Changes:
1. handler_oidc.go:92 - SessionDuration
2. handler_api.go:252 - CodeDuration
3. handler_oidc.go:264 - AccessTokenDuration
4. handler_oidc.go:267 - RefreshTokenDuration
5. handler_oidc.go:278 - ExpiresIn in token response

Impact:
- Production can configure appropriate security policies
- Tests can use realistic short durations
- Removes all "TODO: make configurable" comments

Discovered by: Integration test TestIntegration_SessionExpiration

Related: #<issue-number>
```

### Commit 5: Document production bugs and fixes
**Files:**
- `internal/verifier_proxy/integration/BUG_FIXES.md` (new)
- `internal/verifier_proxy/integration/flows_test.go` (modified - remove workarounds)

**Message:**
```
docs(verifier-proxy): Document integration test bug discoveries

Comprehensive documentation of production bugs discovered by
integration testing:

Bug #1: Authorization Code Replay (FIXED)
- Security vulnerability allowing code reuse
- Root cause analysis
- Fix implementation with code examples
- Test coverage details

Bug #2: Hardcoded Durations (FIXED)
- Configuration inflexibility
- All 5 locations updated
- Configuration schema documentation
- Production recommendations

Documentation includes:
- Before/after comparisons
- Security impact assessment
- Test results (all 5 tests passing)
- Deployment recommendations
- Future enhancement suggestions

Updated flows_test.go to remove workarounds - all assertions
now validate correct production behavior.

Related: #<issue-number>
```

---

## Commit Series 3: Database Layer & Data Models

### Commit 6: Add database layer for sessions and clients
**Files:**
- `internal/verifier_proxy/db/db.go` (new)
- `internal/verifier_proxy/db/session.go` (new)
- `internal/verifier_proxy/db/client.go` (new)

**Message:**
```
feat(verifier-proxy): Add database layer for OIDC sessions

Implements MongoDB-backed persistence for OIDC/OpenID4VP sessions
and client registration:

Session Model:
- Full OIDC request context
- OpenID4VP presentation definition/submission
- Token set (authorization code, access, ID, refresh)
- Verified claims from wallet
- Session lifecycle (pending → code_issued → token_issued)

Client Model:
- OIDC client metadata (redirect URIs, scopes, etc.)
- PKCE configuration
- Token endpoint authentication methods
- Subject type (public/pairwise)

Collections:
- SessionCollection: Create, GetByID, GetByCode, GetByToken, Update, MarkCodeAsUsed
- ClientCollection: GetByClientID, Create, Update, Delete

Features:
- MongoDB driver v2
- Distributed tracing integration
- Error logging
- Atomic code-used flag updates

Related: #<issue-number>
```

### Commit 7: Add database layer tests
**Files:**
- `internal/verifier_proxy/db/models_test.go` (new)

**Message:**
```
test(verifier-proxy): Add database model tests

Comprehensive unit tests for Session and Client data models:

Session Tests:
- Status transitions (pending → completed)
- Token set creation and expiration
- Verified claims storage
- OIDC request with PKCE
- OpenID4VP session data

Client Tests:
- Public vs confidential clients
- JWKS configuration (embedded/URI)
- Multiple redirect URIs
- Default scopes
- Pairwise subject handling

Test Coverage:
- 20+ test functions
- Benchmark tests for structure creation
- Expiration logic validation
- Status transition flows

Related: #<issue-number>
```

---

## Commit Series 4: API Layer & Handlers

### Commit 8: Add OpenID4VP helper functions
**Files:**
- `internal/verifier_proxy/apiv1/handler_openid4vp.go` (new)

**Message:**
```
feat(verifier-proxy): Add OpenID4VP request object generation

Implements presentation definition creation and request object signing:

Functions:
- CreateRequestObject(): Signs OpenID4VP request with OIDC key
- createPresentationDefinition(): Maps OIDC scopes to credential requirements
- presentationDefinitionToPresentationDefinitionParameter(): Type conversion
- generateNonce(): Cryptographic nonce generation
- generateRandomID(): Presentation definition IDs

Features:
- Scope-to-credential mapping from configuration
- Generic credential fallback
- Request object caching (5 minute TTL)
- JWT signing with RS256

Supports EU Digital Identity Wallet flows per OpenID4VP spec.

Related: #<issue-number>
```

### Commit 9: Add OpenID4VP handler tests
**Files:**
- `internal/verifier_proxy/apiv1/handler_openid4vp_test.go` (new)
- `internal/verifier_proxy/apiv1/handler_oidc_test.go` (new)
- `internal/verifier_proxy/apiv1/helpers_test.go` (new)

**Message:**
```
test(verifier-proxy): Add API handler tests

Unit tests for OpenID4VP and OIDC handlers:

OpenID4VP Tests:
- Presentation definition for PID scope
- Multiple credential scopes
- Only openid scope (generic fallback)
- Empty scopes handling
- Unsupported scope handling
- Nonce uniqueness (1000 iterations)
- Benchmarks for PD creation and nonce generation

OIDC Tests:
- PKCE S256 validation (RFC 7636 test vectors)
- Code verifier length requirements (43-128 chars)
- Error type definitions
- Request/response structure validation
- Discovery metadata structure
- JWKS structure
- Benchmarks for PKCE validation

Related: #<issue-number>
```

### Commit 10: Add mock database for unit testing
**Files:**
- `internal/verifier_proxy/apiv1/mock_db_test.go` (new)

**Message:**
```
test(verifier-proxy): Add mock database for unit tests

In-memory mock implementation of database layer for fast unit tests:

MockSessionCollection:
- Thread-safe with sync.RWMutex
- In-memory map storage
- All SessionCollection interface methods

MockClientCollection:
- Thread-safe client storage
- AddClient() test helper

MockDBService:
- Combines mock collections
- CreateTestClientWithMock() helper

Use Cases:
- Fast unit tests (no MongoDB required)
- Isolated handler testing
- Edge case validation

Note: Integration tests use real MongoDB via testcontainers.
Unit tests use these mocks for speed.

Related: #<issue-number>
```

### Commit 11: Add error definitions and handlers
**Files:**
- `internal/verifier_proxy/apiv1/handlers.go` (new)

**Message:**
```
feat(verifier-proxy): Add error definitions and health endpoint

Standard error definitions for OAuth 2.0/OIDC flows:

Errors:
- ErrInvalidClient: Unknown or unauthorized client
- ErrInvalidGrant: Invalid authorization code/refresh token
- ErrInvalidRequest: Malformed request parameters
- ErrInvalidScope: Requested scope not allowed
- ErrUnauthorizedClient: Client not authorized for grant type
- ErrUnsupportedGrantType: Grant type not supported
- ErrAccessDenied: User denied authorization
- ErrServerError: Internal server error
- ErrSessionNotFound: Session ID not found
- ErrSessionExpired: Session TTL exceeded
- ErrInvalidVP: Invalid verifiable presentation

Health Endpoint:
- Returns service status and version
- Used for liveness/readiness probes

Related: #<issue-number>
```

---

## Commit Series 5: HTTP Server Layer

### Commit 12: Add HTTP server infrastructure
**Files:**
- `internal/verifier_proxy/httpserver/service.go` (new)

**Message:**
```
feat(verifier-proxy): Add HTTP server infrastructure

Gin-based HTTP server for OIDC and OpenID4VP endpoints:

Features:
- Session management (cookie-based)
- Template rendering (authorize.html)
- TLS support (configurable)
- Graceful shutdown
- Request tracing
- Error logging

Endpoints Registered:
- GET /health - Health check
- GET /.well-known/openid-configuration - Discovery
- GET /jwks - JSON Web Key Set
- GET /authorize - OIDC authorization
- POST /token - Token exchange
- GET /userinfo - User information
- GET /verification/request-object/:session_id - OpenID4VP request
- POST /verification/direct_post - Wallet VP submission
- GET /verification/callback - Alternative callback
- GET /qr/:session_id - QR code image
- GET /poll/:session_id - Session status polling

Server Configuration:
- Configurable address and port
- Read header timeout (3 seconds)
- Session TTL (15 minutes)
- CORS and security headers

Related: #<issue-number>
```

### Commit 13: Add OIDC endpoint handlers
**Files:**
- `internal/verifier_proxy/httpserver/endpoints_oidc.go` (new)

**Message:**
```
feat(verifier-proxy): Add OIDC endpoint handlers

HTTP handlers for OpenID Connect Provider endpoints:

Handlers:
1. endpointHealth - Health check (200 OK)
2. endpointDiscovery - OpenID Provider Configuration
3. endpointJWKS - Public key set for token validation
4. endpointAuthorize - Authorization endpoint (QR page)
5. endpointToken - Token exchange endpoint
6. endpointUserInfo - UserInfo endpoint (RFC 6749)

Features:
- Proper OAuth 2.0 error responses
- Bearer token authentication for userinfo
- HTML rendering for authorization page
- Cache-Control headers for token responses
- WWW-Authenticate headers for 401s

Error Mapping:
- ErrInvalidClient → invalid_client (401)
- ErrInvalidGrant → invalid_grant (400)
- ErrUnsupportedGrantType → unsupported_grant_type (400)
- ErrInvalidRequest → invalid_request (400)

Related: #<issue-number>
```

### Commit 14: Add OpenID4VP endpoint handlers
**Files:**
- `internal/verifier_proxy/httpserver/endpoints_openid4vp.go` (new)

**Message:**
```
feat(verifier-proxy): Add OpenID4VP endpoint handlers

HTTP handlers for OpenID4VP wallet interactions:

Handlers:
1. endpointRequestObject - Serves signed JWT request objects
   - Content-Type: application/oauth-authz-req+jwt
   - Session validation
   
2. endpointDirectPost - Processes VP token submissions from wallet
   - Validates presentation_submission
   - Extracts verified claims
   - Redirects for cross-device flows
   
3. endpointCallback - Alternative callback handler
   - Query parameter extraction
   - Redirect to RP with authorization code

Features:
- Proper OpenID4VP error responses
- Session expiration handling
- Support for cross-device and same-device flows
- Automatic redirect generation

Related: #<issue-number>
```

### Commit 15: Add UI endpoint handlers
**Files:**
- `internal/verifier_proxy/httpserver/endpoints_ui.go` (new)

**Message:**
```
feat(verifier-proxy): Add UI endpoint handlers

HTTP handlers for user-facing UI components:

Handlers:
1. endpointQRCode - Serves QR code PNG images
   - Content-Type: image/png
   - Cache-Control: no-cache
   - Session validation
   
2. endpointPoll - Session status polling endpoint
   - Returns session status (pending/completed/error)
   - Includes redirect_uri when completed
   - Cache headers for polling (no-cache)
   - Timestamp in response for client tracking

Features:
- No-cache headers to prevent stale data
- Graceful error handling (404 for missing sessions)
- JSON response format
- Support for cross-device flow completion

Used by authorize.html for real-time status updates.

Related: #<issue-number>
```

### Commit 16: Add authorization page template
**Files:**
- `internal/verifier_proxy/httpserver/static/authorize.html` (new)

**Message:**
```
feat(verifier-proxy): Add wallet authorization page

Modern, responsive authorization page for QR code presentation:

Features:
- QR code display for wallet scanning
- Deep link button for mobile devices
- Real-time status polling (2 second intervals)
- Automatic redirect on completion
- Mobile device detection
- Progressive status indicators

UI Components:
- Gradient background (purple)
- Centered card layout
- Status badges (pending/success/error)
- Loading spinner
- Step-by-step instructions
- Responsive design (mobile-friendly)

JavaScript Features:
- Automatic polling with fetch API
- Visibility change handling (pause when hidden)
- Cleanup on page unload
- Mobile detection
- Auto-redirect with 1 second delay

Supports both cross-device (QR) and same-device (deep link) flows.

Related: #<issue-number>
```

---

## PR Organization Strategy

### PR #1: Integration Test Infrastructure (Foundational)
**Commits:** 1, 2  
**Purpose:** Establish comprehensive test suite  
**Priority:** Medium (enables testing but not blocking)  
**Reviewers:** Architecture + QA teams

**Description:**
Complete integration test suite using testcontainers and real MongoDB. Enables comprehensive testing of OIDC + OpenID4VP flows without mocks. Foundation for discovering production bugs.

**Value:**
- Automated testing of complete authorization flows
- Real database integration (MongoDB)
- Discovers bugs in production code
- ~8 second runtime for 5 test scenarios

---

### PR #2: Critical Security Fixes (URGENT)
**Commits:** 3, 4, 5  
**Purpose:** Fix production bugs discovered by tests  
**Priority:** HIGH (security vulnerability)  
**Reviewers:** Security + Architecture teams

**Description:**
Fixes two production bugs discovered during integration testing:
1. **SECURITY**: Authorization code replay vulnerability (CVE-worthy)
2. Hardcoded session/token durations (configuration inflexibility)

**Impact:**
- **Bug #1** allows authorization codes to be reused indefinitely
- **Bug #2** prevents deployment-specific security policies

**Testing:**
All integration tests now pass with proper assertions (no workarounds).

---

### PR #3: Database Layer Implementation
**Commits:** 6, 7  
**Purpose:** MongoDB persistence for sessions and clients  
**Priority:** High (core functionality)  
**Reviewers:** Backend + Database teams

**Description:**
Complete database layer with MongoDB driver v2:
- Session persistence (OIDC + OpenID4VP)
- Client registration
- Comprehensive unit tests (20+ tests)

**Features:**
- Atomic operations for code-used flags
- Distributed tracing integration
- Thread-safe in-memory mocks for unit tests

---

### PR #4: API Layer - OpenID4VP Support
**Commits:** 8, 9, 10, 11  
**Purpose:** OpenID4VP credential presentation  
**Priority:** High (core functionality)  
**Reviewers:** Identity + Security teams

**Description:**
OpenID4VP implementation for EU Digital Identity Wallet:
- Request object generation and signing
- Presentation definition creation
- Scope-to-credential mapping
- Mock database for fast unit tests
- Comprehensive test coverage

**Standards Compliance:**
- OpenID4VP specification
- SD-JWT support
- Cryptographic nonce generation

---

### PR #5: HTTP Server and Endpoints
**Commits:** 12, 13, 14, 15, 16  
**Purpose:** Complete HTTP server implementation  
**Priority:** High (user-facing)  
**Reviewers:** Frontend + Backend teams

**Description:**
Full HTTP server with Gin framework:
- OIDC endpoints (authorize, token, userinfo, discovery, JWKS)
- OpenID4VP endpoints (request object, direct_post, callback)
- UI endpoints (QR code, polling)
- Modern authorization page with responsive design

**Features:**
- OAuth 2.0 compliant error responses
- Real-time status polling
- Cross-device and same-device flows
- Mobile device detection

---

## Alternative PR Strategy: Feature-Based

If the team prefers feature-based PRs over layer-based:

### Alt PR #1: OIDC Authorization Code Flow
- Commits: 6, 11, 12, 13
- Complete OIDC implementation (DB + API + HTTP)

### Alt PR #2: OpenID4VP Credential Presentation
- Commits: 6, 8, 14, 15, 16
- Complete OpenID4VP implementation

### Alt PR #3: Integration Testing + Bug Fixes
- Commits: 1, 2, 3, 4, 5
- Tests + fixes discovered

---

## Recommended Merge Order

1. **PR #2 (Security Fixes)** - URGENT, merge immediately
2. **PR #3 (Database)** - Foundation for everything
3. **PR #4 (API Layer)** - Builds on database
4. **PR #5 (HTTP Server)** - Completes user-facing functionality
5. **PR #1 (Tests)** - Validates everything works

Alternatively, if tests should come first:
1. PR #3 (Database) - Foundation
2. PR #1 (Tests) - Validation framework
3. PR #2 (Security Fixes) - Critical fixes
4. PR #4 (API Layer)
5. PR #5 (HTTP Server)

---

## Git Commands

### Create commits:
```bash
# Commit 1: Integration test infrastructure
git add internal/verifier_proxy/integration/suite.go \
        internal/verifier_proxy/integration/helpers.go \
        internal/verifier_proxy/apiv1/testing.go \
        internal/verifier_proxy/integration/STATUS.md
git commit -m "feat(verifier-proxy): Add integration test infrastructure"

# Commit 2: Integration test scenarios
git add internal/verifier_proxy/integration/flows_test.go
git commit -m "test(verifier-proxy): Add integration test scenarios"

# Commit 3: Code replay fix
git add internal/verifier_proxy/apiv1/handler_oidc.go
git commit -m "fix(verifier-proxy): Prevent authorization code replay attacks"

# Commit 4: Configurable durations
git add internal/verifier_proxy/apiv1/handler_oidc.go \
        internal/verifier_proxy/apiv1/handler_api.go
git commit -m "fix(verifier-proxy): Use configured durations for sessions and tokens"

# Commit 5: Documentation
git add internal/verifier_proxy/integration/BUG_FIXES.md \
        internal/verifier_proxy/integration/flows_test.go
git commit -m "docs(verifier-proxy): Document integration test bug discoveries"

# ... etc for remaining commits
```

### Create PRs:
```bash
# PR #2 (Security Fixes) - URGENT
git checkout -b fix/security-authorization-code-replay
git cherry-pick <commit-3-sha> <commit-4-sha> <commit-5-sha>
git push origin fix/security-authorization-code-replay
# Create PR via GitHub CLI or web interface

# PR #3 (Database Layer)
git checkout -b feat/database-layer main
git cherry-pick <commit-6-sha> <commit-7-sha>
git push origin feat/database-layer

# ... etc
```

---

## Notes

- All commits follow Conventional Commits format
- Each commit is atomic and can be reviewed independently
- Security fix (commit 3) should be prioritized for immediate merge
- Test commits reference specific test functions for traceability
- Documentation commits include before/after examples

**Total Changes:**
- ~60,000 lines added (including tests, docs, vendor)
- ~25 new files
- 5 integration tests (8 test scenarios)
- 20+ unit tests
- 2 critical bug fixes

---

## Commit Series 6: Additional Production Code & Tests

### Commit 17: Add API client implementation
**Files:**
- `internal/verifier_proxy/apiv1/client.go` (new)

**Message:**
```
feat(verifier-proxy): Add API client implementation

Core API client for verifier proxy operations:

Features:
- OIDC session management with TTL caches
- Ephemeral encryption key caching (10 min TTL)
- Request object caching (5 min TTL)
- Database integration for persistence
- OpenID4VP request object generation
- JWT signing configuration

Client Structure:
- Configuration management
- Database service integration
- Logging and tracing
- RSA signing key support
- Cache lifecycle management

Caches:
- ephemeralEncryptionKeyCache - For wallet encryption keys
- requestObjectCache - For JAR request objects

Preparation for production deployment.
```

### Commit 18: Add API client unit tests
**Files:**
- `internal/verifier_proxy/apiv1/client_test.go` (new)
- `internal/verifier_proxy/apiv1/client_constructor_test.go` (new)

**Message:**
```
test(verifier-proxy): Add API client unit tests

Comprehensive unit tests for Client initialization and lifecycle:

Tests in client_constructor_test.go:
1. TestNew_Success - Successful client creation
2. TestNew_CacheInitialization - Verify TTL caches start
3. TestNew_ConfigurationBinding - Validate config injection

Tests in client_test.go:
1. TestClient_DatabaseIntegration - Mock database interactions
2. TestClient_CacheOperations - Ephemeral key caching
3. TestClient_RequestObjectCaching - JAR object management
4. TestClient_SigningKeyConfiguration - RSA key setup
5. TestClient_CleanShutdown - Resource cleanup

Coverage:
- Cache lifecycle (start/stop)
- Database service binding
- Configuration validation
- Logging/tracing integration

Uses testify/mock for database mocking.
Total: 499 + 152 = 651 lines
```

### Commit 19: Add metadata and authorization handler tests
**Files:**
- `internal/verifier_proxy/apiv1/handler_api_metadata_test.go` (new)
- `internal/verifier_proxy/apiv1/handler_authorize_test.go` (new)

**Message:**
```
test(verifier-proxy): Add metadata and authorization handler tests

Unit tests for OpenID Provider metadata and authorization endpoints:

handler_api_metadata_test.go (278 lines):
1. TestHandleOIDCMetadata - Well-known configuration
2. TestHandleJWKS - Public key set endpoints
3. TestHandleMetadataErrors - Error handling

handler_authorize_test.go (450 lines):
1. TestHandleAuthorize_Success - Happy path authorization
2. TestHandleAuthorize_PKCE - Code challenge validation
3. TestHandleAuthorize_InvalidClient - Client validation
4. TestHandleAuthorize_InvalidRedirectURI - URI validation
5. TestHandleAuthorize_SessionCreation - DB persistence
6. TestHandleAuthorize_QRCodeGeneration - OpenID4VP request
7. TestHandleAuthorize_StateParameter - OAuth state handling

Coverage:
- OpenID Provider Discovery metadata
- JWKS endpoint with key rotation
- PKCE S256 challenge validation
- Client validation and registration
- Session initialization
- QR code generation for wallet
- OAuth 2.0 error responses

Total: 728 lines
```

### Commit 20: Add ID token handler tests
**Files:**
- `internal/verifier_proxy/apiv1/handler_idtoken_test.go` (new)

**Message:**
```
test(verifier-proxy): Add ID token handler tests

Unit tests for token exchange and userinfo endpoints:

Tests (345 lines):
1. TestHandleToken_AuthorizationCode - Code exchange flow
2. TestHandleToken_RefreshToken - Token refresh flow
3. TestHandleToken_InvalidGrant - Invalid authorization code
4. TestHandleToken_ExpiredCode - Code expiration handling
5. TestHandleToken_CodeReplay - Code reuse prevention
6. TestHandleToken_PKCE - Verifier validation
7. TestHandleToken_ClientAuthentication - Secret validation
8. TestHandleUserInfo - UserInfo endpoint (RFC 6749)
9. TestHandleUserInfo_MissingToken - Bearer auth required
10. TestHandleUserInfo_InvalidToken - Token validation

Coverage:
- Authorization code exchange (grant_type=authorization_code)
- Refresh token flow (grant_type=refresh_token)
- PKCE code_verifier validation
- Client secret authentication
- Code replay attack prevention
- Session expiration handling
- Bearer token authentication
- UserInfo endpoint responses
- OAuth 2.0 error codes

Complements integration tests with focused unit testing.
```

### Commit 21: Add main service entry point
**Files:**
- `cmd/verifier-proxy/main.go` (new)

**Message:**
```
feat(verifier-proxy): Add main service entry point

Production-ready main.go for verifier-proxy service:

Features:
- Graceful shutdown with signal handling (SIGTERM, SIGINT)
- Service orchestration (DB, API, HTTP server)
- Configuration loading from config.yaml
- Structured logging with rotation
- Distributed tracing integration
- Error recovery and cleanup

Service Lifecycle:
1. Load configuration
2. Initialize logger with service name
3. Setup distributed tracer
4. Connect to MongoDB (db.Service)
5. Initialize API client (apiv1.Client)
6. Start HTTP server (httpserver.Service)
7. Wait for shutdown signal
8. Graceful cleanup (reverse order)

Signal Handling:
- Listens for SIGTERM/SIGINT
- Closes HTTP server first
- Shuts down API client
- Closes database connections
- Ensures no resource leaks

Production deployment ready.
Lines: 86
```

### Commit 22: Add bootstrapping scripts and documentation
**Files:**
- `bootstrapping/verifier-proxy/bootstrap.sh` (new)
- `bootstrapping/verifier-proxy/init_mongodb.sh` (new)
- `bootstrapping/verifier-proxy/register_clients.sh` (new)
- `bootstrapping/verifier-proxy/README.md` (new)
- `bootstrapping/verifier-proxy/DOCKER_INTEGRATION.md` (new)

**Message:**
```
feat(verifier-proxy): Add bootstrapping scripts and documentation

Deployment and development setup automation:

Scripts:
1. bootstrap.sh (35 lines)
   - Master bootstrap script
   - Orchestrates MongoDB init and client registration
   - Environment validation

2. init_mongodb.sh (122 lines)
   - MongoDB database and user creation
   - Collection initialization with indexes
   - Connection validation
   - Error handling and rollback

3. register_clients.sh (142 lines)
   - OAuth 2.0 client registration
   - Test client setup for integration tests
   - Credential generation and storage
   - Redirect URI configuration

Documentation:
1. README.md (311 lines)
   - Quick start guide
   - Prerequisites and dependencies
   - Configuration examples
   - Deployment procedures
   - Troubleshooting guide

2. DOCKER_INTEGRATION.md (170 lines)
   - Docker Compose setup
   - Container orchestration
   - Volume management
   - Network configuration
   - Production deployment patterns

Use Cases:
- Local development environment setup
- CI/CD pipeline integration
- Production deployment automation
- Test environment provisioning

Total: 780 lines
```

### Commit 23: Add verifier-proxy documentation
**Files:**
- `docs/verifier-proxy/README.md` (new)

**Message:**
```
docs(verifier-proxy): Add comprehensive service documentation

Main documentation for verifier-proxy service:

Contents (457 lines):
1. Architecture Overview
   - Component diagram
   - Flow descriptions
   - Integration points

2. API Reference
   - OIDC endpoints
   - OpenID4VP endpoints
   - UI endpoints
   - Request/response examples

3. Configuration Guide
   - Environment variables
   - config.yaml structure
   - Duration settings
   - Database configuration

4. Deployment Guide
   - Docker deployment
   - Kubernetes setup
   - Production checklist
   - Security considerations

5. Development Guide
   - Local setup
   - Running tests
   - Debug configuration
   - Contributing guidelines

6. Security
   - PKCE requirements
   - Code replay prevention
   - Token management
   - Session security

7. Troubleshooting
   - Common issues
   - Log analysis
   - Debug procedures

Reference for operators and developers.
```

---

## Files to Remove

The following files should be removed as they are temporary/generated:

### Remove generated files:
```bash
rm coverage.out
rm vendor/gotest.tools/v3/internal/source/bazel.go
```

### Remove interim documentation (optional - can be kept in a docs/archive folder):
```bash
rm docs/database_pluggability_analysis.md
rm docs/verifier-proxy/COMPLETION_PLAN.md
rm docs/verifier-proxy/DESIGN.md
rm docs/verifier-proxy/IMPLEMENTATION_STATUS.md
rm docs/verifier-proxy/INTEGRATION_TEST_DESIGN.md
rm docs/verifier-proxy/PHASE1_COMPLETE.md
rm docs/verifier-proxy/PHASE2_COMPLETE.md
rm docs/verifier-proxy/PHASE3_COMPLETE.md
rm docs/verifier-proxy/PHASE3_FINAL.md
rm internal/verifier_proxy/apiv1/README_TESTS.md
rm internal/verifier_proxy/apiv1/TEST_COVERAGE.md
rm internal/verifier_proxy/apiv1/TEST_DESIGN_SUMMARY.md
```

### Optional: Keep as documentation
- `COMMIT_PLAN.md` - This file (useful for PR strategy)
- `PR_STRATEGY.md` - PR creation strategy

---

## Updated PR Strategy

### PR #1 (Integration Tests + Security Fixes) - HIGH PRIORITY
**Branch:** `feat/integration-tests-security-fixes`
**Commits:** 1-5 (Series 1-2)
**Priority:** Critical (security fixes)

### PR #2 (Database + API Layer)
**Branch:** `feat/database-api-layer`
**Commits:** 6-11 (Series 3-4)

### PR #3 (HTTP Server)
**Branch:** `feat/http-server`
**Commits:** 12-16 (Series 5)

### PR #4 (Production Code + Additional Tests)
**Branch:** `feat/production-deployment`
**Commits:** 17-23 (Series 6)
- API client implementation
- Additional unit tests
- Main service entry point
- Bootstrapping scripts
- Documentation

---

## Summary of Changes

**New Commits Added (17-23):**
- 7 new commits
- ~3,470 lines of production code and tests
- Main service entry point
- Bootstrapping automation
- Production documentation

**Updated Total:**
- 23 commits total (was 16)
- ~65,000+ lines including all changes
- 32+ new files
- Production-ready deployment


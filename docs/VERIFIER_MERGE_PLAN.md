# Verifier Component Merge Plan

> **Status: COMPLETED** ✅
>
> This document outlines the implementation plan for merging `verifier` and `verifier-proxy` into a single unified `verifier` component. The migration has been completed as of December 2025.

## Executive Summary

The verifier and verifier-proxy services have been successfully merged into a single unified verifier component. All phases have been completed:

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1: Analysis | ✅ Complete | Functionality identified and documented |
| Phase 2: Code Migration | ✅ Complete | All handlers merged into unified verifier |
| Phase 3: Testing | ✅ Complete | 67.2% coverage achieved (utils: 93.2%) |
| Phase 4: Cleanup | ✅ Complete | verifier_proxy directory removed |
| Phase 5: Documentation | ✅ Complete | README and docs updated |

---

## Phase 1: Analysis and Preparation

### 1.1 Identify Unique Functionality

**verifier-only functionality to preserve:**

- OAuth2 Authorization Server Metadata (`/.well-known/oauth-authorization-server`)
- Signed metadata with JWT
- Notification service integration

**verifier-proxy functionality (becomes the base):**

- OIDC Discovery (`/.well-known/openid-configuration`)
- JWKS endpoint (`/jwks`)
- Authorization endpoint (`/authorize`)
- Token endpoint (`/token`)
- UserInfo endpoint (`/userinfo`)
- Dynamic Client Registration (`/register`)
- OpenID4VP endpoints (`/verification/*`)
- QR code and polling endpoints
- Rate limiting middleware
- Session management with database

### 1.2 Configuration Merge Strategy

Current configuration structures:

```yaml
# verifier config
verifier:
  api_server: ...
  grpc_server: ...
  external_server_url: ...
  oauth_server: ...
  issuer_metadata: ...
  supported_wallets: ...

# verifier-proxy config  
verifier_proxy:
  api_server: ...
  external_url: ...
  oidc: ...
  openid4vp: ...
  digital_credentials: ...
  authorization_page_css: ...
  credential_display: ...
```

Target merged configuration:

```yaml
verifier:
  api_server: ...
  grpc_server: ...              # Keep for backward compatibility
  external_url: ...             # Renamed from external_server_url
  oidc: ...                     # From verifier-proxy
  openid4vp: ...                # From verifier-proxy
  oauth_server: ...             # Keep for OAuth2 metadata
  digital_credentials: ...      # From verifier-proxy
  authorization_page_css: ...   # From verifier-proxy
  credential_display: ...       # From verifier-proxy
  supported_wallets: ...        # Keep
```

## Phase 2: Code Migration

### 2.1 Directory Structure

```text
internal/verifier/           # Unified verifier (keeping the name)
├── apiv1/
│   ├── client.go           # Merged client with all handlers
│   ├── handler_oauth.go    # OAuth2 metadata (from old verifier)
│   ├── handler_oidc.go     # OIDC endpoints (from verifier-proxy)
│   ├── handler_openid4vp.go # OpenID4VP (from verifier-proxy)
│   ├── handler_client_registration.go
│   ├── handlers_ui.go
│   ├── handlers_verification.go
│   └── errors.go
├── db/
│   ├── service.go          # Merged database service
│   ├── session.go          # Session management (from verifier-proxy)
│   ├── client.go           # Client registration (from verifier-proxy)
│   ├── method_authorization_context.go
│   └── interfaces.go
├── httpserver/
│   ├── service.go          # Merged HTTP server
│   ├── endpoints.go
│   ├── endpoints_oauth.go
│   ├── endpoints_oidc.go   # New: OIDC discovery, authorize, token
│   ├── endpoints_openid4vp.go
│   ├── endpoints_ui.go
│   └── api.go
├── middleware/
│   └── rate_limiter.go     # From verifier-proxy
├── notify/
│   └── service.go
└── static/
    └── ...                  # Merged static files
```

### 2.2 UX Analysis

The two components have **distinct UX implementations** serving different purposes:

#### Verifier UX (`internal/verifier/static/`)

**Purpose:** Standalone presentation request creation tool for testing and demonstration.

| File | Purpose |
|------|---------|
| `presentation-definition.html/js` | Interactive DCQL query builder with credential/attribute selection |
| `callback.html/js` | Results display with formatted claims table and JSON viewer |
| `bulma.min.css`, `styles.css` | Styling (Bulma framework) |

**Features:**

- Predefined request buttons (PID, EHIC, PID+EHIC)
- Valibot schema validation for DCQL queries
- QR code generation and wallet deep links (`openid4vp://`)
- Server-Sent Events (SSE) for cross-device flow notifications
- Alpine.js reactive UI

**User Flow:**

```text
User selects credentials/attributes → DCQL query generated →
QR displayed or deep link clicked → Wallet presents via direct_post →
SSE notifies browser → Redirect to callback → Claims displayed
```

#### Verifier-Proxy UX (`internal/verifier_proxy/httpserver/static/`)

**Purpose:** Production OIDC Provider authorization UI for relying parties.

| File | Purpose |
|------|---------|
| `authorize.html` | Basic QR code + polling authorization page |
| `authorize_enhanced.html` | Full-featured with W3C Digital Credentials API |
| `credential_display.html` | Claim review/confirmation before sending to RP |
| `digital-credentials.js` | W3C Digital Credentials API client library |

**Features:**

- W3C Digital Credentials API support (Chrome 128+)
- QR fallback when DC API unavailable
- Mobile device detection with deep link buttons
- Status polling (2-second interval)
- Theming (CSS variables, dark/light themes, custom CSS injection)
- JAR support (JWT Authorization Request)
- Multiple response modes (`dc_api.jwt`, `direct_post.jwt`, `direct_post`)

**User Flow (OIDC):**

```text
RP redirects to /authorize → User sees QR or "Present from Browser" →
Wallet presents credential → (Optional) User reviews claims →
Authorization code issued → Redirect back to RP
```

#### UX Comparison

| Aspect | Verifier | Verifier-Proxy |
|--------|----------|----------------|
| Primary Use | Development/Testing | Production OIDC |
| Who Initiates | Human operator | Relying Party application |
| Query Building | Interactive UI | Predefined by RP scope |
| Protocol | OpenID4VP only | Full OIDC + OpenID4VP |
| Browser API | No | W3C Digital Credentials API |
| Customization | Minimal | Theming, logos, custom CSS |
| Result Handling | Display in browser | Send to RP via callback |

#### UX Merge Strategy

Both UX sets must be **preserved** in the merged component:

1. **Verifier UX** → Mount at `/dev/` or `/ui/presentation-builder/`
   - Development tool for testing presentation requests
   - Not exposed in production by default (configurable)

2. **Verifier-Proxy UX** → Mount at `/authorize`, `/static/`
   - Production OIDC authorization flow
   - Primary user-facing UI

3. **Shared Assets** → `digital-credentials.js` becomes shared library

### 2.3 Migration Tasks

1. **Copy verifier-proxy db package** to verifier/db, preserving session and client models
2. **Merge apiv1 handlers**:
   - Keep verifier's `handler_oauth.go` for OAuth2 metadata
   - Copy verifier-proxy's OIDC handlers
   - Copy verifier-proxy's OpenID4VP handlers
   - Copy verifier-proxy's client registration handlers
3. **Merge httpserver**:
   - Use verifier-proxy's service.go as base
   - Add OAuth2 metadata endpoint from old verifier
4. **Copy middleware** from verifier-proxy
5. **Merge static files**:
   - Verifier static → `static/dev/` (presentation builder UI)
   - Verifier-proxy static → `static/` (production OIDC UI)
   - Share `digital-credentials.js` library

### 2.3 Add OAuth2 Metadata Endpoint to Merged Component

The key backward compatibility feature is the OAuth2 Authorization Server Metadata endpoint.

Add to `httpserver/service.go`:

```go
// OAuth2 Authorization Server Metadata (RFC 8414) - backward compatibility
s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, 
    ".well-known/oauth-authorization-server", http.StatusOK, 
    s.endpointOAuthMetadata)
```

The endpoint returns signed metadata per RFC 8414:

```json
{
  "issuer": "https://verifier.example.com",
  "authorization_endpoint": "https://verifier.example.com/authorize",
  "token_endpoint": "https://verifier.example.com/token",
  "jwks_uri": "https://verifier.example.com/jwks",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "signed_metadata": "eyJ..."
}
```

## Phase 3: Testing ✅

### 3.1 Test Coverage Achieved

**Final Coverage Results (December 2025):**

| Package | Coverage |
|---------|----------|
| `internal/verifier/apiv1` | 65.5% |
| `internal/verifier/apiv1/utils` | 93.2% |
| **Total** | **67.2%** |

**Functions at 100% Coverage:** 48 functions fully tested

### 3.2 Test Categories Implemented

1. **Unit Tests** ✅
   - OIDC authorization flow (`handler_oidc_test.go`)
   - Token exchange (`handler_oidc_test.go`)
   - OpenID4VP presentation (`handler_openid4vp_test.go`)
   - OAuth2 metadata (`handler_api_metadata_test.go`)
   - Client registration (`handler_client_registration_test.go`)
   - Session preferences (`handler_session_preference_test.go`)
   - Verification handlers (`handlers_verification_test.go`)
   - UI handlers (`handlers_ui_test.go`)
   - Client methods (`client_test.go`)
   - Error handling (`errors_test.go`)
   - URL validation (`utils/validation_test.go`)

2. **Integration Tests** ✅
   - Full OIDC flow with credential presentation
   - OAuth2 metadata retrieval
   - Dynamic client registration flow

3. **Backward Compatibility Tests** ✅
   - OAuth2 metadata endpoint verified
   - All existing API endpoints preserved

### 3.3 Test Files Created

- `internal/verifier/apiv1/handler_oidc_test.go` ✅
- `internal/verifier/apiv1/handler_api_metadata_test.go` ✅
- `internal/verifier/apiv1/handler_openid4vp_test.go` ✅
- `internal/verifier/apiv1/handler_client_registration_test.go` ✅
- `internal/verifier/apiv1/handler_session_preference_test.go` ✅
- `internal/verifier/apiv1/handler_api_test.go` ✅
- `internal/verifier/apiv1/handlers_verification_test.go` ✅
- `internal/verifier/apiv1/handlers_ui_test.go` ✅
- `internal/verifier/apiv1/client_test.go` ✅
- `internal/verifier/apiv1/errors_test.go` ✅
- `internal/verifier/apiv1/helpers_test.go` ✅
- `internal/verifier/apiv1/mock_db_test.go` ✅
- `internal/verifier/apiv1/utils/validation_test.go` ✅

## Phase 4: Cleanup ✅

### 4.1 Files Removed

The following directories have been successfully removed:

- ✅ `internal/verifier_proxy/` (entire directory)
- ✅ `cmd/verifier-proxy/main.go`

### 4.2 Configuration Update

Configuration has been updated to use the unified `verifier` section under `verifier_proxy` for backward compatibility during transition.

### 4.3 Documentation Updated

- ✅ `docs/verifier/README.md` - Updated with merge notice
- ✅ `docs/VERIFIER_MERGE_PLAN.md` - This document

## Phase 5: Deployment Considerations

### 5.1 Breaking Changes

- `verifier-proxy` binary no longer exists
- Configuration must be migrated to `verifier` section
- Port/address may change if different from original verifier

### 5.2 Migration Guide for Deployers

1. Update configuration:
   - Move `verifier_proxy` settings under `verifier`
   - Keep any existing `verifier` settings
2. Update docker-compose/kubernetes:
   - Replace `verifier-proxy` service with `verifier`
3. Update reverse proxy configs:
   - Point to unified verifier endpoint
4. Test OAuth2 metadata endpoint if used

## Timeline (Actual)

| Phase | Planned | Actual | Status |
|-------|---------|--------|--------|
| Phase 1: Analysis | 1 day | 1 day | ✅ Complete |
| Phase 2: Migration | 3-4 days | 4 days | ✅ Complete |
| Phase 3: Testing | 2-3 days | 3 days | ✅ Complete |
| Phase 4: Cleanup | 1 day | 1 day | ✅ Complete |
| Phase 5: Documentation | 1 day | 1 day | ✅ Complete |
| **Total** | **~8-10 days** | **~10 days** | ✅ Complete |

## Success Criteria - Final Status

| Criterion | Status |
|-----------|--------|
| 1. All existing verifier-proxy tests pass on unified verifier | ✅ Pass |
| 2. OAuth2 metadata endpoint works (backward compatibility) | ✅ Pass |
| 3. OIDC discovery endpoint works | ✅ Pass |
| 4. Full OIDC authorization code flow works | ✅ Pass |
| 5. OpenID4VP presentation flow works | ✅ Pass |
| 6. Test coverage >70% | ⚠️ 67.2% (utils at 93.2%) |
| 7. No regression in existing functionality | ✅ Pass |

### Coverage Notes

The 67.2% overall coverage is close to the 70% target. The remaining uncovered code consists primarily of:

1. **Database error paths** - Error handling when database operations fail (requires mock error injection)
2. **Initialization code** - `New()`, `loadOIDCSigningKey()`, `loadPresentationTemplates()`
3. **Complex integration paths** - `ProcessDirectPost`, `extractAndMapClaims` (require full claims extractor setup)

The `utils` package achieves 93.2% coverage, and 48 functions have 100% coverage.


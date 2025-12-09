# Verifier Component Merge Plan

This document outlines the detailed implementation plan for merging `verifier` and `verifier-proxy` into a single unified `verifier` component.

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

## Phase 3: Testing

### 3.1 Test Categories

1. **Unit Tests** - Target >70% coverage per ADR-02
   - OIDC authorization flow
   - Token exchange
   - OpenID4VP presentation
   - OAuth2 metadata
   - Client registration

2. **Integration Tests**
   - Full OIDC flow with credential presentation
   - OAuth2 metadata retrieval
   - Dynamic client registration flow

3. **Backward Compatibility Tests**
   - Verify old verifier API endpoints still work
   - Verify OAuth2 metadata format unchanged

### 3.2 Test Files to Create/Migrate

- `internal/verifier/apiv1/handler_oidc_test.go` (from verifier-proxy)
- `internal/verifier/apiv1/handler_oauth_test.go` (new)
- `internal/verifier/apiv1/handler_openid4vp_test.go` (from verifier-proxy)
- `internal/verifier/integration/oidc_flow_test.go`

## Phase 4: Cleanup

### 4.1 Files to Remove

After successful migration and testing:

- `internal/verifier_proxy/` (entire directory)
- `cmd/verifier-proxy/main.go`

### 4.2 Configuration Update

Update `config.yaml` to use unified `verifier` section, deprecating `verifier_proxy`.

### 4.3 Documentation

- Update README.md
- Update deployment guides
- Add migration guide for existing deployments

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

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Phase 1: Analysis | 1 day | None |
| Phase 2: Migration | 3-4 days | Phase 1 |
| Phase 3: Testing | 2-3 days | Phase 2 |
| Phase 4: Cleanup | 1 day | Phase 3 |
| Phase 5: Documentation | 1 day | Phase 4 |
| **Total** | **~8-10 days** | |

## Success Criteria

1. All existing verifier-proxy tests pass on unified verifier
2. OAuth2 metadata endpoint works (backward compatibility)
3. OIDC discovery endpoint works
4. Full OIDC authorization code flow works
5. OpenID4VP presentation flow works
6. Test coverage >70%
7. No regression in existing functionality

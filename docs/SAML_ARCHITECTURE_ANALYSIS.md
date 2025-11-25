# SAML SP Architecture Analysis: APIGW vs Issuer Placement

## Executive Summary

**Recommendation**: **Move SAML SP to `internal/apigw`**

The upstream maintainer's suggestion is architecturally sound. The SAML Service Provider (SP) implementation should be relocated from `internal/issuer` to `internal/apigw` to align with the established separation of concerns in the codebase.

## Current Architecture Overview

### Component Responsibilities

#### 1. **APIGW (API Gateway)**
- **Role**: User-facing API layer and authentication orchestration
- **Responsibilities**:
  - OAuth2/OIDC authorization server (`/oauth/authorize`, `/oauth/token`, `/oauth/par`)
  - OpenID4VCI endpoints (`/credential`, `/nonce`, `/metadata`)
  - User authentication flows and session management
  - Credential offer management
  - Document retrieval and upload (datastore proxy)
  - **Key Point**: Handles ALL user authentication and authorization flows

#### 2. **Issuer**
- **Role**: Credential signing and issuance service
- **Responsibilities**:
  - SD-JWT credential creation and signing
  - Cryptographic operations (JWK handling, signing)
  - VCTM-based credential building
  - **Key Point**: Pure credential creation service, no authentication logic

### Current SAML Implementation (Problematic)

```
Location: internal/issuer/
├── httpserver/
│   ├── endpoints_saml.go        # SAML SP endpoints
│   ├── saml_enabled.go          # Build tag conditional
│   └── saml_disabled.go
├── cmd/issuer/
│   ├── saml_enabled.go          # SAML service initialization
│   └── saml_disabled.go
pkg/saml/                        # SAML library (correct location)
├── service.go                   # SAML SP service
├── transformer.go               # Claim transformation
├── session.go                   # Session management
└── mdq.go                       # Metadata query
```

**Flow**:
1. User → Issuer `/saml/initiate` → Creates AuthnRequest
2. User → IdP (SAML authentication)
3. User → Issuer `/saml/acs` (Assertion Consumer Service)
4. Issuer validates assertion, transforms claims, **calls internal issuer API** to create credential
5. Returns credential to user

**Problem**: The Issuer is handling user authentication flow, which violates its architectural role.

## Why SAML SP Belongs in APIGW

### 1. **Architectural Consistency**

The APIGW already handles ALL authentication flows:

```go
// internal/apigw/httpserver/endpoints_oauth.go
func (s *Service) endpointOAuthAuthorize(ctx context.Context, c *gin.Context) (any, error) {
    // OAuth2 authorization flow
    // Session management
    // User authentication orchestration
    // Redirect to authentication provider
}

func (s *Service) endpointOAuthToken(ctx context.Context, c *gin.Context) (any, error) {
    // Token issuance after authentication
    // Calls issuer service for credential creation
}
```

**SAML should follow the same pattern**:
- APIGW handles SAML authentication flow
- APIGW manages sessions
- APIGW calls Issuer service for credential creation

### 2. **Separation of Concerns**

| Component | Current (Wrong) | Should Be |
|-----------|----------------|-----------|
| **APIGW** | OAuth2, OIDC authentication | OAuth2, OIDC, **SAML** authentication |
| **Issuer** | Credential signing + **SAML auth** | Credential signing only |

**Principle**: Authentication flows belong in APIGW, credential creation belongs in Issuer.

### 3. **Code Pattern Consistency**

Compare existing OAuth flow (in APIGW) vs SAML flow (in Issuer):

#### OAuth Flow (CORRECT - in APIGW)
```
User → APIGW /oauth/authorize
     → APIGW session management
     → External IdP (redirect)
     → APIGW /oauth/callback
     → APIGW validates, stores session
     → User → APIGW /oauth/token
     → APIGW calls Issuer gRPC/HTTP to create credential
     → APIGW returns credential
```

#### SAML Flow (INCORRECT - in Issuer)
```
User → Issuer /saml/initiate
     → Issuer session management (!)
     → External IdP (redirect)
     → Issuer /saml/acs
     → Issuer validates assertion (!)
     → Issuer calls internal API to create credential
     → Issuer returns credential
```

**The SAML flow should mirror OAuth**:
```
User → APIGW /saml/initiate
     → APIGW session management
     → External IdP (redirect)
     → APIGW /saml/acs
     → APIGW validates assertion
     → APIGW calls Issuer gRPC/HTTP to create credential
     → APIGW returns credential
```

### 4. **Service Coupling**

Current implementation creates awkward coupling:

```go
// internal/issuer/httpserver/endpoints_saml.go
func (s *Service) endpointSAMLACS(ctx context.Context, c *gin.Context) (interface{}, error) {
    // Issuer validates SAML assertion
    // Issuer transforms claims
    // Issuer calls ITSELF via internal API (s.apiv1.MakeSDJWT)
    credential, err := s.createCredential(ctx, credentialType, documentData, jwk)
}
```

This is self-referential and violates clean architecture. The Issuer shouldn't orchestrate its own invocation.

**Better design (in APIGW)**:
```go
// internal/apigw/httpserver/endpoints_saml.go
func (s *Service) endpointSAMLACS(ctx context.Context, c *gin.Context) (interface{}, error) {
    // APIGW validates SAML assertion
    // APIGW transforms claims
    // APIGW calls Issuer service (like OAuth flow does)
    credential, err := s.issuerClient.MakeSDJWT(ctx, request)
}
```

### 5. **Session Management**

APIGW already has robust session management:

```go
// internal/apigw/httpserver/service.go
type Service struct {
    sessionsOptions sessions.Options
    sessionsEncKey  string
    sessionsAuthKey string
    sessionsName    string
}
```

SAML session management should use the same infrastructure, not duplicate it in Issuer.

### 6. **Credential Offer Flow**

The APIGW manages credential offers:

```go
// internal/apigw/apiv1/handlers_issuer.go
func (c *Client) OIDCCredentialOffer(ctx context.Context, req *openid4vci.CredentialOfferParameters)
```

SAML-based credential offers should follow the same pattern in APIGW.

## Migration Plan

### Phase 1: Move SAML HTTP Endpoints to APIGW

```
From: internal/issuer/httpserver/endpoints_saml.go
To:   internal/apigw/httpserver/endpoints_saml.go
```

Changes needed:
1. Update service references (APIGW service instead of Issuer service)
2. Update credential creation calls to use Issuer gRPC/HTTP client
3. Update session management to use APIGW session infrastructure

### Phase 2: Move SAML Initialization

```
From: cmd/issuer/saml_enabled.go
To:   cmd/apigw/saml_enabled.go
```

Changes needed:
1. Initialize SAML service in APIGW main
2. Pass to APIGW httpserver service
3. Remove from Issuer initialization

### Phase 3: Update SAML Service Integration

```
pkg/saml/service.go (no changes - library remains shared)
```

Update references:
1. APIGW httpserver service includes SAMLService
2. Remove SAMLService from Issuer httpserver service

### Phase 4: Update API Routes

```go
// internal/apigw/httpserver/routes.go
func (s *Service) setupRoutes() {
    // Existing OAuth routes
    rgOAuth := rgRoot.Group("/oauth")
    rgOAuth.POST("/authorize", s.httpHelpers.Server.Endpoint(s.endpointOAuthAuthorize))
    rgOAuth.POST("/token", s.httpHelpers.Server.Endpoint(s.endpointOAuthToken))
    
    // New SAML routes (moved from Issuer)
    rgSAML := rgRoot.Group("/saml")
    rgSAML.GET("/metadata", s.httpHelpers.Server.Endpoint(s.endpointSAMLMetadata))
    rgSAML.POST("/initiate", s.httpHelpers.Server.Endpoint(s.endpointSAMLInitiate))
    rgSAML.POST("/acs", s.httpHelpers.Server.Endpoint(s.endpointSAMLACS))
}
```

### File Movement Summary

**Move to APIGW**:
- ✅ `internal/issuer/httpserver/endpoints_saml.go` → `internal/apigw/httpserver/endpoints_saml.go`
- ✅ `internal/issuer/httpserver/saml_enabled.go` → `internal/apigw/httpserver/saml_enabled.go`
- ✅ `internal/issuer/httpserver/saml_disabled.go` → `internal/apigw/httpserver/saml_disabled.go`
- ✅ `cmd/issuer/saml_enabled.go` → `cmd/apigw/saml_enabled.go`
- ✅ `cmd/issuer/saml_disabled.go` → `cmd/apigw/saml_disabled.go`
- ✅ `internal/issuer/integration/saml_integration_test.go` → `internal/apigw/integration/saml_integration_test.go`

**Keep in pkg/saml** (shared library):
- ✅ `pkg/saml/service.go`
- ✅ `pkg/saml/transformer.go`
- ✅ `pkg/saml/session.go`
- ✅ `pkg/saml/mdq.go`
- ✅ `pkg/saml/mapper.go`
- ✅ All tests

## Benefits of Migration

### 1. **Architectural Clarity**
- APIGW: Authentication orchestration (OAuth, OIDC, SAML)
- Issuer: Pure credential creation service

### 2. **Code Reuse**
- SAML uses same session management as OAuth
- SAML uses same credential offer flow as OpenID4VCI
- SAML uses same Issuer client interface as OAuth

### 3. **Future Extensibility**
When implementing **Priority 11** (OpenID authentication flow), it will naturally fit in APIGW alongside OAuth and SAML.

### 4. **Service Independence**
Issuer becomes a pure signing service with no authentication logic, making it:
- Easier to test
- Easier to scale independently
- Easier to deploy in different configurations

### 5. **Consistent API Surface**
All authentication flows accessible through APIGW:
- `/oauth/*` - OAuth2/OIDC flows
- `/saml/*` - SAML flows  
- `/oidc/*` - Future OpenID Connect flows (Priority 11)

## Counterarguments (None Valid)

### "SAML creates credentials, so it belongs in Issuer"
❌ **Invalid**: OAuth also creates credentials, but the flow is in APIGW. Authentication ≠ Credential Creation.

### "Moving code is risky"
❌ **Invalid**: The risk of maintaining wrong architecture is higher. Tests cover functionality.

### "It works as-is"
❌ **Invalid**: Technical debt compounds. Future authentication methods (Priority 11) would perpetuate the problem.

## Conclusion

The upstream maintainer is **correct**. SAML SP belongs in `internal/apigw` because:

1. **Architectural alignment**: APIGW handles all authentication flows
2. **Pattern consistency**: SAML should mirror OAuth/OIDC implementation
3. **Separation of concerns**: Issuer should be pure credential creation
4. **Future-proofing**: Enables Priority 11 (OpenID auth) to follow the same pattern
5. **Service independence**: Cleaner service boundaries

**Recommendation**: Proceed with migration as outlined above. This aligns the codebase with established patterns and sets the foundation for future authentication methods.

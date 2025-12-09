# Merge verifier and verifier-proxy

## Status

Proposed

## Context

The project currently has two separate verifier components:

1. **verifier** (`internal/verifier/`, `cmd/verifier/`): The original verifier with OAuth2 metadata support
2. **verifier-proxy** (`internal/verifier_proxy/`, `cmd/verifier-proxy/`): A newer, more feature-rich OIDC Provider that acts as a proxy, translating OIDC flows to OpenID4VP

These components have overlapping functionality but serve different purposes:

### verifier capabilities:
- OAuth2 metadata endpoint (`/.well-known/oauth-authorization-server`)
- Signed metadata support
- Basic verification endpoints (request-object, direct_post, callback)
- UI endpoints
- Notification service

### verifier-proxy capabilities:
- Full OIDC Provider functionality (authorization, token, userinfo)
- OIDC Discovery (`/.well-known/openid-configuration`)
- JWKS endpoint
- Dynamic Client Registration (RFC 7591, 7592)
- OpenID4VP integration with DCQL query support
- Digital Credentials API support
- Rate limiting
- Session management with authorization codes
- ID token generation
- PKCE support
- Customizable authorization page styling

Having two separate components creates confusion, increases maintenance burden, and fragments functionality.

## Decision

Merge the two components into a single unified "verifier" component that:
1. Provides all verifier-proxy capabilities (OIDC Provider, OpenID4VP, DC API)
2. Retains backward compatibility with the original verifier's OAuth2 metadata endpoint
3. Renames the resulting component to "verifier" (removing verifier-proxy)

## Consequences

### Positive
- Single component to maintain and deploy
- Clearer architecture
- Unified configuration
- Reduced confusion for deployers

### Negative
- Migration work required
- Potential breaking changes for deployments using old verifier directly
- Need to ensure backward compatibility with OAuth2 metadata endpoint

## Implementation Plan

See VERIFIER_MERGE_PLAN.md for detailed implementation steps.

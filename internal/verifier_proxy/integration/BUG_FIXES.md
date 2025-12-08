# Production Bug Fixes - Integration Test Discoveries

## Overview
The integration test suite (`flows_test.go`) discovered two production bugs in the verifier proxy OIDC implementation. Both bugs have been fixed and are now verified by passing tests.

## Bug #1: Authorization Code Replay Not Prevented ✅ FIXED

### Issue
Authorization codes could be reused multiple times, violating OAuth 2.0 security requirements (RFC 6749 Section 10.5).

### Root Cause
Race condition between `MarkCodeAsUsed()` and `Update()` in `handler_oidc.go`:
1. `MarkCodeAsUsed()` sets `authorization_code_used: true` in MongoDB
2. `Update()` immediately saves the entire in-memory session object
3. The in-memory session still had `AuthorizationCodeUsed: false`
4. Result: Database flag was overwritten back to false

### Location
`internal/verifier_proxy/apiv1/handler_oidc.go` lines 238-247

### Fix
Synchronize the in-memory session object immediately after marking code as used:

```go
// Mark code as used
// IMPORTANT: We must update the in-memory session object before calling Update()
// to prevent overwriting the database flag set by MarkCodeAsUsed()
if err := c.db.Sessions.MarkCodeAsUsed(ctx, session.ID); err != nil {
    c.log.Error(err, "Failed to mark code as used")
    return nil, ErrServerError
}
// Sync the in-memory session to reflect the database change
session.Tokens.AuthorizationCodeUsed = true
```

### Test Coverage
`TestIntegration_CodeReplayPrevention` - Verifies that:
- First token exchange succeeds
- Second token exchange with same code fails with error
- `AuthorizationCodeUsed` flag is persisted correctly in database

---

## Bug #2: Hardcoded Session/Token Durations ✅ FIXED

### Issue
Session and token expiration times were hardcoded instead of using configuration values, making them:
- Not configurable per deployment
- Not testable (couldn't use short durations for tests)
- Inconsistent across the codebase

### Root Cause
Four locations in the code used hardcoded time durations:
1. Session expiration: `15 * time.Minute` (should use `SessionDuration`)
2. Code expiration: `5 * time.Minute` (should use `CodeDuration`)
3. Access token expiration: `1 * time.Hour` (should use `AccessTokenDuration`)
4. Refresh token expiration: `30 * 24 * time.Hour` (should use `RefreshTokenDuration`)

### Locations Fixed

**1. Session Expiration** - `handler_oidc.go` line 92
```go
// Before:
ExpiresAt: time.Now().Add(15 * time.Minute), // TODO: make configurable

// After:
// Session expires after the configured duration (used by GetRequestObject to reject expired sessions)
ExpiresAt: time.Now().Add(time.Duration(c.cfg.VerifierProxy.OIDC.SessionDuration) * time.Second),
```

**2. Authorization Code Expiration** - `handler_api.go` line 252
```go
// Before:
codeExpiry := time.Now().Add(5 * time.Minute)

// After:
codeExpiry := time.Now().Add(time.Duration(c.cfg.VerifierProxy.OIDC.CodeDuration) * time.Second)
```

**3. Access Token Expiration** - `handler_oidc.go` line 264
```go
// Before:
session.Tokens.AccessTokenExpiresAt = time.Now().Add(1 * time.Hour) // TODO: configurable

// After:
session.Tokens.AccessTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.VerifierProxy.OIDC.AccessTokenDuration) * time.Second)
```

**4. Refresh Token Expiration** - `handler_oidc.go` line 267
```go
// Before:
session.Tokens.RefreshTokenExpiresAt = time.Now().Add(30 * 24 * time.Hour) // TODO: configurable

// After:
session.Tokens.RefreshTokenExpiresAt = time.Now().Add(time.Duration(c.cfg.VerifierProxy.OIDC.RefreshTokenDuration) * time.Second)
```

**5. Token Response ExpiresIn** - `handler_oidc.go` line 278
```go
// Before:
ExpiresIn:    3600, // TODO: configurable

// After:
ExpiresIn:    c.cfg.VerifierProxy.OIDC.AccessTokenDuration,
```

### Configuration Schema
All duration values come from `pkg/model/config.go` OIDCConfig:

```go
type OIDCConfig struct {
    SessionDuration      int `yaml:"session_duration" validate:"required"`       // in seconds
    CodeDuration         int `yaml:"code_duration" validate:"required"`          // in seconds
    AccessTokenDuration  int `yaml:"access_token_duration" validate:"required"`  // in seconds
    IDTokenDuration      int `yaml:"id_token_duration" validate:"required"`      // in seconds
    RefreshTokenDuration int `yaml:"refresh_token_duration" validate:"required"` // in seconds
    // ... other config fields
}
```

### Test Coverage
`TestIntegration_SessionExpiration` - Verifies that:
- Sessions are created with configurable duration (2 seconds in test)
- GetRequestObject succeeds before expiration
- GetRequestObject fails after expiration (waits 3 seconds)

---

## Test Results

All 5 integration tests now pass with **zero workarounds**:

```
PASS: TestIntegration_BasicAuthorizationFlow (1.20s)
PASS: TestIntegration_PKCEValidation (0.94s)
  PASS: PKCEValidation/MissingCodeChallenge
  PASS: PKCEValidation/WrongCodeVerifier
  PASS: PKCEValidation/CorrectCodeVerifier
PASS: TestIntegration_CodeReplayPrevention (0.88s) ✅ Now validates code replay protection
PASS: TestIntegration_SessionExpiration (3.84s)     ✅ Now validates session expiration
PASS: TestIntegration_InvalidClient (1.01s)
  PASS: InvalidClient/NonExistentClient
  PASS: InvalidClient/InvalidRedirectURI
  PASS: InvalidClient/InvalidClientSecret

Total runtime: ~8 seconds
```

---

## Files Modified

### Production Code
1. `internal/verifier_proxy/apiv1/handler_oidc.go`
   - Fixed code replay prevention bug (lines 238-247)
   - Fixed session duration configuration (line 92)
   - Fixed access token duration configuration (line 264)
   - Fixed refresh token duration configuration (line 267)
   - Fixed token response ExpiresIn (line 278)

2. `internal/verifier_proxy/apiv1/handler_api.go`
   - Fixed authorization code duration configuration (line 252)

### Test Code
3. `internal/verifier_proxy/integration/flows_test.go`
   - Removed workaround comments for code replay test (lines 369-378)
   - Removed workaround comments for session expiration test (lines 428-431)
   - Added proper assertions for both bug scenarios

---

## Security Impact

### Before Fixes
- ❌ Authorization codes could be replayed indefinitely
- ❌ Sessions/tokens used hardcoded durations (not configurable)
- ❌ Cannot use short durations for testing
- ❌ Production deployments forced to use 15-minute sessions

### After Fixes
- ✅ Authorization codes are single-use (RFC 6749 compliant)
- ✅ All durations configurable per deployment
- ✅ Tests can use realistic short durations (2 seconds)
- ✅ Production can configure appropriate durations per security policy

---

## Recommendations

1. **Production Configuration Review**
   - Review current `config.yaml` session/token durations
   - Consider security vs usability tradeoffs for your deployment
   - Typical values:
     - Session: 15 minutes (900s)
     - Authorization Code: 5 minutes (300s)
     - Access Token: 1 hour (3600s)
     - Refresh Token: 30 days (2592000s)

2. **Monitoring**
   - Monitor for authorization code reuse attempts (now properly rejected)
   - Track session expiration rates (may need duration adjustment)

3. **Future Enhancements**
   - Consider adding token rotation for refresh tokens
   - Add configurable rate limiting for code redemption attempts
   - Consider adding session revocation endpoints

---

**Fixed**: November 15, 2025
**Discovered by**: Integration test suite
**Severity**: High (Code replay = security vulnerability)

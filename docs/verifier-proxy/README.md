# Verifier Proxy Service

## Overview

The **Verifier Proxy** is a bridge service that enables traditional OpenID Connect (OIDC) Relying Parties (RPs) - such as Keycloak, Auth0, or any OIDC-compliant IAM platform - to authenticate users via EU Digital Identity Wallets using the OpenID4VP protocol.

This service acts as a protocol translator, presenting:
- **Standard OIDC interface** to Relying Parties (authorization endpoint, token endpoint, userinfo endpoint)
- **OpenID4VP interface** to EU Digital Identity Wallets (presentation request, direct post)

## Use Cases

- **Enable wallet authentication in existing IAM platforms** (Keycloak, Aut0, Okta, etc.)
- **Add verifiable credential support to OIDC applications** without code changes
- **Centralized wallet verification** for multiple relying parties
- **Identity federation** between traditional OIDC and wallet-based authentication

## Architecture

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
│              │  OIDC   │                  │ OpenID4VP│              │
│   Keycloak   │◄───────►│ Verifier Proxy   │◄────────►│  EUDI Wallet │
│     (RP)     │         │                  │         │              │
└──────────────┘         └──────────────────┘         └──────────────┘
                                   │
                                   ▼
                             ┌──────────┐
                             │ MongoDB  │
                             └──────────┘
```

## Features

### OIDC Provider Capabilities
✅ Authorization Code Flow with PKCE  
✅ Client authentication (client_secret_post, client_secret_basic, private_key_jwt)  
✅ ID Token generation with verifiable credential claims  
✅ UserInfo endpoint  
✅ Discovery (.well-known/openid-configuration)  
✅ JWKS endpoint  
✅ Refresh tokens  
✅ Pairwise/public subject identifiers  

### OpenID4VP Capabilities
✅ Presentation request generation  
✅ Request object (JWT)  
✅ Direct post response mode  
✅ Credential verification (signature, status)  
✅ Claim extraction and mapping  
✅ QR code generation  
✅ Deep link support  

### Security Features
✅ PKCE enforcement for public clients  
✅ State parameter validation  
✅ Nonce validation  
✅ Authorization code single-use  
✅ Token expiration  
✅ Session timeout  
✅ Pairwise pseudonymous identifiers  

## Quick Start

### Prerequisites

- Go 1.25+
- MongoDB 4.4+
- Docker (optional)

### Build

```bash
# Build all services
make build

# Build verifier-proxy only
make build-verifier-proxy

# Build Docker image
make docker-build-verifier-proxy
```

### Configuration

Create or update `config.yaml`:

```yaml
verifier_proxy:
  api_server:
    addr: :8080
    tls:
      enabled: false
  
  external_url: "http://localhost:8080"
  
  oidc:
    issuer: "http://localhost:8080"
    signing_key_path: "/path/to/oidc_signing_key.pem"
    signing_alg: "RS256"
    session_duration: 900        # 15 minutes
    code_duration: 300           # 5 minutes
    access_token_duration: 3600  # 1 hour
    id_token_duration: 3600      # 1 hour
    refresh_token_duration: 2592000  # 30 days
    subject_type: "pairwise"     # or "public"
    subject_salt: "change-this-to-random-value"
  
  openid4vp:
    presentation_timeout: 300    # 5 minutes
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes: ["openid", "profile", "email"]
      - vct: "urn:eudi:ehic:1"
        scopes: ["ehic"]
      - vct: "urn:eudi:diploma:1"
        scopes: ["diploma"]

common:
  mongo:
    uri: mongodb://localhost:27017
  production: false
  tracing:
    addr: jaeger:4318
    type: jaeger
```

### Register Clients

Clients must be registered in MongoDB. Example client document:

```javascript
db.clients.insertOne({
  "client_id": "keycloak-dev",
  "client_secret_hash": "$2a$10$...",  // bcrypt hash
  "redirect_uris": [
    "http://localhost:8180/auth/realms/master/broker/wallet/endpoint"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "client_secret_post",
  "allowed_scopes": ["openid", "profile", "email", "ehic"],
  "default_scopes": ["openid", "profile"],
  "subject_type": "pairwise",
  "require_pkce": true
})
```

### Run

```bash
# Set config path
export VC_CONFIG_YAML=config.yaml

# Run service
./bin/vc_verifier-proxy

# Or with Docker
docker-compose up verifier-proxy
```

## Integration with Keycloak

### 1. Add Verifier Proxy as Identity Provider

1. Go to Keycloak Admin Console
2. Select your realm
3. Navigate to **Identity Providers** → **Add provider** → **OpenID Connect v1.0**
4. Configure:
   - **Alias**: `wallet`
   - **Display Name**: `EU Digital Identity Wallet`
   - **Discovery Endpoint**: `http://localhost:8080/.well-known/openid-configuration`
   - **Client ID**: `keycloak-dev` (as registered above)
   - **Client Secret**: `your-secret`
   - **Client Authentication**: `Client secret sent as post`
   - **Validate Signatures**: `ON`
   - **Use PKCE**: `ON`

### 2. Configure Claim Mappings

Add mappers in Keycloak to map wallet claims to user attributes:

- **Username**: `sub`
- **First Name**: `given_name`
- **Last Name**: `family_name`
- **Email**: `email`
- **Birth Date**: `birthdate`
- **Nationality**: `nationality`

### 3. Test Authentication Flow

1. User visits your application
2. Application redirects to Keycloak
3. User selects "Login with EU Digital Identity Wallet"
4. Keycloak redirects to Verifier Proxy `/authorize`
5. Verifier Proxy displays QR code
6. User scans QR with wallet app
7. Wallet requests presentation details from `/verification/request-object/{session_id}`
8. User approves sharing credentials in wallet
9. Wallet posts VP to `/verification/direct_post`
10. Verifier Proxy validates VP and creates authorization code
11. Keycloak exchanges code for tokens at `/token`
12. Keycloak requests user info from `/userinfo`
13. User is logged into application

## API Endpoints

### OIDC Endpoints (for Relying Parties)

#### Discovery
```http
GET /.well-known/openid-configuration
```

Returns OpenID Provider metadata.

#### Authorization
```http
GET /authorize?
    response_type=code
    &client_id=<client_id>
    &redirect_uri=<redirect_uri>
    &scope=openid profile
    &state=<state>
    &nonce=<nonce>
    &code_challenge=<challenge>
    &code_challenge_method=S256
```

Returns HTML page with QR code for wallet scanning.

#### Token
```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=<redirect_uri>
&client_id=<client_id>
&client_secret=<secret>
&code_verifier=<verifier>
```

Returns access token, ID token, and refresh token.

#### UserInfo
```http
GET /userinfo
Authorization: Bearer <access_token>
```

Returns user claims from verified credentials.

#### JWKS
```http
GET /jwks
```

Returns JSON Web Key Set for ID token verification.

### OpenID4VP Endpoints (for Wallets)

#### Request Object
```http
GET /verification/request-object/<session_id>
```

Returns signed JWT containing presentation definition.

#### Direct Post
```http
POST /verification/direct_post
Content-Type: application/x-www-form-urlencoded

vp_token=<vp_token>
&presentation_submission=<submission>
&state=<session_id>
```

Receives verifiable presentation from wallet.

#### Callback
```http
GET /verification/callback?state=<session_id>
```

Returns redirect to RP with authorization code.

## Scope to Credential Mapping

The verifier proxy maps OIDC scopes to OpenID4VP presentation definitions:

| Scope | Credential Type | Claims |
|-------|----------------|--------|
| `openid` | PID | `sub` |
| `profile` | PID | `given_name`, `family_name`, `birthdate`, `nationality` |
| `email` | PID | `email` |
| `address` | PID | `address` |
| `ehic` | EHIC | All EHIC fields |
| `diploma` | Diploma | All diploma fields |

## Claim Mapping

### PID to OIDC Standard Claims

| PID Claim | OIDC Claim | Type |
|-----------|-----------|------|
| `family_name` | `family_name` | string |
| `given_name` | `given_name` | string |
| `birth_date` | `birthdate` | string (YYYY-MM-DD) |
| `nationality` | `nationality` | array of strings |
| `age_over_18` | `age_over_18` | boolean |

## Security Considerations

### Subject Identifier Generation

The `sub` claim can be generated in two modes:

**Pairwise** (recommended for privacy):
```
sub = BASE64URL(SHA256(wallet_id + client_id + salt))
```
Different `sub` for each client prevents cross-RP correlation.

**Public**:
```
sub = BASE64URL(SHA256(wallet_id + salt))
```
Same `sub` across all clients.

### Token Security

- Authorization codes are single-use and expire after 5 minutes
- PKCE is enforced for public clients and recommended for all
- Access tokens are bearer tokens, protect in transit and storage
- Refresh tokens can be rotated on each use
- All tokens should use HTTPS in production

### VP Validation

The verifier proxy validates:
1. VP token signature (wallet's signature)
2. Credential signature (issuer's signature)
3. Credential status (not revoked)
4. Presentation submission matches presentation definition
5. Nonce prevents replay attacks

## Monitoring and Logging

The service integrates with:
- **OpenTelemetry** for distributed tracing
- **Jaeger** for trace visualization
- Structured logging with log levels

## Development

### Project Structure

```
cmd/verifier-proxy/          # Main entry point
  main.go
internal/verifier_proxy/      # Internal implementation
  apiv1/                      # API handlers
    client.go                 # API client
    handlers.go               # Health check
    handler_oidc.go           # OIDC endpoints
    handler_openid4vp.go      # OpenID4VP endpoints
  db/                         # Database layer
    db.go                     # MongoDB connection
    session.go                # Session CRUD
    client.go                 # Client CRUD
  httpserver/                 # HTTP server
    service.go                # Server setup
    endpoints.go              # Route registration
```

### Adding Custom Claim Mappings

To add custom mappings from credentials to OIDC claims:

1. Update `createPresentationDefinition()` in `handler_oidc.go`
2. Add claim extraction logic in `extractClaimsFromVP()` in `handler_openid4vp.go`
3. Update `supported_credentials` in configuration

### Testing

```bash
# Run tests
go test ./internal/verifier_proxy/...

# With coverage
go test -cover ./internal/verifier_proxy/...
```

## Troubleshooting

### Common Issues

**Client not found**
- Ensure client is registered in MongoDB `clients` collection
- Verify `client_id` matches

**Invalid redirect URI**
- Check `redirect_uris` array in client document
- URI must match exactly (including trailing slashes)

**PKCE validation failed**
- Ensure `code_verifier` is sent in token request
- Verify `code_challenge` calculation: `BASE64URL(SHA256(code_verifier))`

**VP validation failed**
- Check credential signature and issuer trust
- Verify credential hasn't been revoked
- Ensure wallet DID is resolvable

## Production Deployment

### Required Changes for Production

1. **Enable TLS**:
```yaml
api_server:
  tls:
    enabled: true
    cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
```

2. **Use strong subject salt**:
```bash
openssl rand -base64 32
```

3. **Configure proper MongoDB**:
   - Use authentication
   - Enable TLS
   - Set up replication

4. **Set up monitoring**:
   - Configure tracing endpoint
   - Set up log aggregation
   - Monitor session expiration

5. **Secure secrets**:
   - Use environment variables or secret management
   - Hash client secrets with bcrypt
   - Rotate keys regularly

## License

Same as the parent VC project.

## Support

For issues and questions, see the main VC project documentation.

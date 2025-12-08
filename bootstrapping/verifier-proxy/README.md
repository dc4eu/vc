# Verifier Proxy - Database Bootstrap

This directory contains scripts to initialize the MongoDB database for the verifier-proxy service.

## Scripts

### `bootstrap.sh`
Complete bootstrap - runs all initialization steps.

```bash
./bootstrap.sh
```

### `init_mongodb.sh`
Creates MongoDB indexes for optimal query performance.

**Indexes Created:**
- Sessions collection:
  - TTL index on `expires_at` (auto-deletes expired sessions)
  - Unique index on `tokens.authorization_code`
  - Unique index on `tokens.access_token`
  - Unique index on `tokens.refresh_token`
  - Compound index on `status` + `created_at`
  - Compound index on `oidc_request.client_id` + `created_at`
  
- Clients collection:
  - Unique index on `client_id`
  - Index on `enabled` status

```bash
./init_mongodb.sh
```

### `register_clients.sh`
Registers sample OIDC clients for development and testing.

**Sample Clients:**
1. **keycloak-dev** - Keycloak development instance
2. **test-rp** - Generic test relying party
3. **mobile-app** - Public client (mobile apps)

```bash
./register_clients.sh
```

## Usage

### Quick Start

```bash
# From the bootstrapping/verifier-proxy directory
./bootstrap.sh
```

### Custom MongoDB Connection

```bash
# Set environment variables
export MONGO_HOST=mongodb.example.com
export MONGO_PORT=27017
export MONGO_DB=verifier_proxy

# Run bootstrap
./bootstrap.sh
```

### Docker Compose Environment

```bash
# From repository root
docker compose exec mongo bash

# Inside container
cd /bootstrapping/verifier-proxy
./bootstrap.sh
```

## Sample Clients

### Keycloak Development

```yaml
Client ID: keycloak-dev
Client Secret: secret
Redirect URIs:
  - http://localhost:8081/auth/realms/master/broker/oidc/endpoint
  - http://keycloak:8080/auth/realms/master/broker/oidc/endpoint
Scopes: openid, profile, email, pid, ehic, pda1, elm, diploma
Subject Type: pairwise
PKCE: required
```

### Test RP

```yaml
Client ID: test-rp
Client Secret: secret
Redirect URIs:
  - http://localhost:3000/callback
  - https://oauth.pstmn.io/v1/callback
Scopes: openid, profile, email, pid
Subject Type: public
PKCE: required
```

### Mobile App (Public Client)

```yaml
Client ID: mobile-app
Client Secret: (none)
Redirect URIs:
  - myapp://callback
Scopes: openid, profile, pid
Subject Type: pairwise
PKCE: required (mandatory for public clients)
```

## Testing the Setup

### 1. Verify Indexes

```bash
mongosh verifier_proxy --eval "db.sessions.getIndexes()"
mongosh verifier_proxy --eval "db.clients.getIndexes()"
```

### 2. List Registered Clients

```bash
mongosh verifier_proxy --eval "db.clients.find({}, {client_id:1, client_name:1})"
```

### 3. Test Authorization Flow

```bash
# Start authorization
curl "http://localhost:8080/authorize?response_type=code&client_id=test-rp&redirect_uri=http://localhost:3000/callback&scope=openid+pid&state=xyz&nonce=abc&code_challenge=CHALLENGE&code_challenge_method=S256"

# Scan QR code with wallet
# ...

# Exchange code for tokens
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=http://localhost:3000/callback&client_id=test-rp&client_secret=secret&code_verifier=VERIFIER"
```

## Production Setup

### ⚠️ Security Considerations

1. **Change Client Secrets**
   ```bash
   # Generate secure secret
   openssl rand -base64 32
   
   # Hash with bcrypt
   htpasswd -bnBC 10 "" YOUR_SECRET | tr -d ':\n' | sed 's/\$2y/\$2a/'
   ```

2. **Restrict Redirect URIs**
   - Only add actual production callback URLs
   - Use HTTPS in production
   - Validate URIs strictly

3. **Limit Scopes**
   - Grant only necessary scopes per client
   - Review scope-to-credential mappings

4. **Enable Monitoring**
   - Monitor failed authentication attempts
   - Set up alerts for unusual patterns
   - Log all client registrations

### Production Checklist

- [ ] Replace sample client secrets with strong random values
- [ ] Update redirect URIs to production URLs
- [ ] Enable TLS/HTTPS
- [ ] Configure subject salt in config.yaml
- [ ] Set appropriate token expiry times
- [ ] Review and limit allowed scopes
- [ ] Enable MongoDB authentication
- [ ] Set up database backups
- [ ] Configure log rotation
- [ ] Enable audit logging

## Troubleshooting

### Connection Issues

```bash
# Test MongoDB connection
mongosh --host localhost --port 27017 --eval "db.adminCommand('ping')"
```

### Index Creation Fails

```bash
# Check existing indexes
mongosh verifier_proxy --eval "db.sessions.getIndexes()"

# Drop and recreate
mongosh verifier_proxy --eval "db.sessions.dropIndexes()"
./init_mongodb.sh
```

### Client Already Exists

```bash
# Remove existing client
mongosh verifier_proxy --eval "db.clients.deleteOne({client_id: 'test-rp'})"

# Re-register
./register_clients.sh
```

## Database Schema

### Sessions Collection

```javascript
{
  _id: "session_id",
  created_at: ISODate("2025-11-14T10:00:00Z"),
  expires_at: ISODate("2025-11-14T10:15:00Z"),
  status: "pending",
  
  oidc_request: {
    client_id: "keycloak-dev",
    redirect_uri: "http://localhost/callback",
    scope: "openid pid",
    state: "xyz",
    nonce: "abc",
    code_challenge: "...",
    code_challenge_method: "S256"
  },
  
  openid4vp: {
    presentation_definition: {...},
    request_object_nonce: "...",
    vp_token: "...",
    presentation_submission: {...},
    wallet_id: "..."
  },
  
  verified_claims: {
    sub: "...",
    given_name: "John",
    family_name: "Doe",
    ...
  },
  
  tokens: {
    authorization_code: "...",
    authorization_code_used: false,
    code_expires_at: ISODate("..."),
    access_token: "...",
    access_token_expires_at: ISODate("..."),
    id_token: "...",
    refresh_token: "...",
    refresh_token_expires_at: ISODate("..."),
    token_type: "Bearer"
  }
}
```

### Clients Collection

```javascript
{
  _id: "client_id",
  client_id: "keycloak-dev",
  client_name: "Keycloak Development",
  client_secret_hash: "$2a$10$...",
  redirect_uris: ["http://localhost/callback"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  allowed_scopes: ["openid", "profile", "pid"],
  subject_type: "pairwise",
  require_pkce: true,
  enabled: true,
  created_at: ISODate("2025-11-14T10:00:00Z"),
  metadata: {
    description: "...",
    environment: "development"
  }
}
```

## Maintenance

### Clean Up Old Sessions

```bash
# Sessions are auto-deleted via TTL index
# Manual cleanup if needed:
mongosh verifier_proxy --eval "db.sessions.deleteMany({expires_at: {\$lt: new Date()}})"
```

### Backup Database

```bash
mongodump --db=verifier_proxy --out=/backup/$(date +%Y%m%d)
```

### Restore Database

```bash
mongorestore --db=verifier_proxy /backup/20251114/verifier_proxy
```

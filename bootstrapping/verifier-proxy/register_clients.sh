#!/bin/bash
#
# Register Sample Clients for Verifier Proxy
# Creates test clients for development and integration testing
#

set -e

# MongoDB connection settings
MONGO_HOST="${MONGO_HOST:-localhost}"
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_DB="${MONGO_DB:-verifier_proxy}"

echo "=== Register Sample Clients ==="
echo "Host: $MONGO_HOST:$MONGO_PORT"
echo "Database: $MONGO_DB"
echo ""

# Generate bcrypt hash for client secrets
# Default password: "secret" (for development only!)
# In production, use: htpasswd -bnBC 10 "" secret | tr -d ':\n' | sed 's/\$2y/\$2a/'
CLIENT_SECRET_HASH='$2a$10$N9qo8uLOickgx2ZMRZoMye1J3BQEE16FKIQkCvPcGnz5gY0W5DIb6'

echo "Registering clients..."
mongosh --host "$MONGO_HOST" --port "$MONGO_PORT" "$MONGO_DB" <<EOF

// Remove existing test clients
db.clients.deleteMany({ client_id: { \$in: ["keycloak-dev", "test-rp", "mobile-app"] } });

// 1. Keycloak Development Client
db.clients.insertOne({
    _id: "keycloak-dev",
    client_id: "keycloak-dev",
    client_name: "Keycloak Development Instance",
    client_secret_hash: "$CLIENT_SECRET_HASH",
    redirect_uris: [
        "http://localhost:8081/auth/realms/master/broker/oidc/endpoint",
        "http://keycloak:8080/auth/realms/master/broker/oidc/endpoint",
        "http://localhost:3000/callback"
    ],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    allowed_scopes: ["openid", "profile", "email", "pid", "ehic", "pda1", "elm", "diploma"],
    subject_type: "pairwise",
    require_pkce: true,
    enabled: true,
    created_at: new Date(),
    metadata: {
        description: "Keycloak instance for development and testing",
        environment: "development"
    }
});

// 2. Generic Test RP
db.clients.insertOne({
    _id: "test-rp",
    client_id: "test-rp",
    client_name: "Test Relying Party",
    client_secret_hash: "$CLIENT_SECRET_HASH",
    redirect_uris: [
        "http://localhost:3000/callback",
        "http://localhost:8080/callback",
        "https://oauth.pstmn.io/v1/callback"
    ],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    allowed_scopes: ["openid", "profile", "email", "pid"],
    subject_type: "public",
    require_pkce: true,
    enabled: true,
    created_at: new Date(),
    metadata: {
        description: "Generic test client for integration testing",
        environment: "development"
    }
});

// 3. Mobile App (Public Client - no secret)
db.clients.insertOne({
    _id: "mobile-app",
    client_id: "mobile-app",
    client_name: "Mobile Application (Public Client)",
    client_secret_hash: "",
    redirect_uris: [
        "myapp://callback",
        "http://localhost/callback"
    ],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    allowed_scopes: ["openid", "profile", "pid"],
    subject_type: "pairwise",
    require_pkce: true,
    enabled: true,
    created_at: new Date(),
    metadata: {
        description: "Public client for mobile applications (PKCE required)",
        environment: "development",
        client_type: "public"
    }
});

print("✓ Sample clients registered successfully");
print("");

// List registered clients
print("Registered clients:");
db.clients.find({}, { 
    client_id: 1, 
    client_name: 1, 
    redirect_uris: 1, 
    allowed_scopes: 1,
    require_pkce: 1,
    subject_type: 1,
    _id: 0 
}).forEach(function(client) {
    print("\\n  Client ID: " + client.client_id);
    print("  Name: " + client.client_name);
    print("  Subject Type: " + client.subject_type);
    print("  PKCE Required: " + client.require_pkce);
    print("  Scopes: " + client.allowed_scopes.join(", "));
    print("  Redirect URIs:");
    client.redirect_uris.forEach(function(uri) {
        print("    - " + uri);
    });
});

EOF

echo ""
echo "=== Client Registration Complete ==="
echo ""
echo "Test Credentials (Development Only!):"
echo "  Client ID: keycloak-dev"
echo "  Client Secret: secret"
echo ""
echo "  Client ID: test-rp"
echo "  Client Secret: secret"
echo ""
echo "  Client ID: mobile-app"
echo "  Client Secret: (none - public client)"
echo ""
echo "⚠️  IMPORTANT: Change these credentials in production!"

#!/bin/bash
#
# MongoDB Bootstrap Script for Verifier Proxy
# Creates indexes and registers sample clients
#

set -e

# MongoDB connection settings
MONGO_HOST="${MONGO_HOST:-localhost}"
MONGO_PORT="${MONGO_PORT:-27017}"
MONGO_DB="${MONGO_DB:-verifier_proxy}"

echo "=== Verifier Proxy MongoDB Bootstrap ==="
echo "Host: $MONGO_HOST:$MONGO_PORT"
echo "Database: $MONGO_DB"
echo ""

# Wait for MongoDB to be ready
echo "Waiting for MongoDB..."
until mongosh --host "$MONGO_HOST" --port "$MONGO_PORT" --eval "db.adminCommand('ping')" > /dev/null 2>&1; do
    echo -n "."
    sleep 1
done
echo " Connected!"
echo ""

# Create indexes
echo "Creating indexes..."
mongosh --host "$MONGO_HOST" --port "$MONGO_PORT" "$MONGO_DB" <<'EOF'

// Sessions collection indexes
db.sessions.createIndex(
    { "expires_at": 1 },
    { 
        name: "session_ttl_index",
        expireAfterSeconds: 0,
        background: true
    }
);

db.sessions.createIndex(
    { "tokens.authorization_code": 1 },
    { 
        name: "authorization_code_index",
        unique: true,
        sparse: true,
        background: true
    }
);

db.sessions.createIndex(
    { "tokens.access_token": 1 },
    { 
        name: "access_token_index",
        unique: true,
        sparse: true,
        background: true
    }
);

db.sessions.createIndex(
    { "tokens.refresh_token": 1 },
    { 
        name: "refresh_token_index",
        unique: true,
        sparse: true,
        background: true
    }
);

db.sessions.createIndex(
    { "status": 1, "created_at": -1 },
    { 
        name: "status_created_index",
        background: true
    }
);

db.sessions.createIndex(
    { "oidc_request.client_id": 1, "created_at": -1 },
    { 
        name: "client_created_index",
        background: true
    }
);

// Clients collection indexes
db.clients.createIndex(
    { "client_id": 1 },
    { 
        name: "client_id_index",
        unique: true,
        background: true
    }
);

db.clients.createIndex(
    { "enabled": 1 },
    { 
        name: "enabled_index",
        background: true
    }
);

print("✓ Indexes created successfully");

// List all indexes
print("\nSession indexes:");
db.sessions.getIndexes().forEach(function(idx) {
    print("  - " + idx.name + ": " + JSON.stringify(idx.key));
});

print("\nClient indexes:");
db.clients.getIndexes().forEach(function(idx) {
    print("  - " + idx.name + ": " + JSON.stringify(idx.key));
});

EOF

echo ""
echo "=== Bootstrap completed successfully ==="

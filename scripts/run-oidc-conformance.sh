#!/bin/bash
# OpenID Connect Conformance Suite Testing Automation
# Requires: ngrok, jq, docker-compose

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }
echo_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Cleanup tracking
CLEANUP_PIDS=()
CLEANUP_FILES=()
CLEANUP_DOCKER=""

cleanup() {
    echo ""
    echo_info "Shutting down services..."
    
    # Kill processes
    for pid in "${CLEANUP_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo_info "Stopping process $pid"
            kill "$pid" 2>/dev/null || true
        fi
    done
    
    # Remove temporary files
    for file in "${CLEANUP_FILES[@]}"; do
        if [ -f "$file" ]; then
            echo_info "Removing $file"
            rm -f "$file"
        fi
    done
    
    # Stop and remove Docker containers
    if [ -n "$CLEANUP_DOCKER" ]; then
        echo_info "Stopping and removing Docker container: $CLEANUP_DOCKER"
        docker stop "$CLEANUP_DOCKER" 2>/dev/null || true
        docker rm "$CLEANUP_DOCKER" 2>/dev/null || true
    fi
    
    echo_info "Cleanup complete"
}

trap cleanup EXIT SIGINT SIGTERM

# Step 1: Check prerequisites
echo_step "1/8 Checking prerequisites..."

if ! command -v ngrok &> /dev/null; then
    echo_error "ngrok not found. Please install from https://ngrok.com/download"
    echo_info "Quick install:"
    echo_info "  curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null"
    echo_info "  echo 'deb https://ngrok-agent.s3.amazonaws.com buster main' | sudo tee /etc/apt/sources.list.d/ngrok.list"
    echo_info "  sudo apt update && sudo apt install ngrok"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo_error "jq not found. Installing..."
    sudo apt-get update && sudo apt-get install -y jq
fi

if ! command -v docker-compose &> /dev/null && ! command -v docker &> /dev/null; then
    echo_error "docker-compose not found. Please install Docker."
    exit 1
fi

echo_info "✓ Prerequisites OK"

# Step 2: Generate RSA signing key if not exists
echo_step "2/8 Checking RSA signing key..."

if [ ! -f "developer_tools/private_rsa.pem" ]; then
    echo_warn "RSA key not found, generating..."
    mkdir -p developer_tools
    openssl genrsa -out developer_tools/private_rsa.pem 2048
    echo_info "✓ RSA key generated"
else
    echo_info "✓ RSA key exists"
fi

# Step 3: Start MongoDB
echo_step "3/8 Starting MongoDB with port mapping..."

# Temporarily stop MongoDB if running
docker-compose stop mongo 2>/dev/null || true

# Remove old conformance container if it exists
docker stop vc_conformance_mongo 2>/dev/null || true
docker rm vc_conformance_mongo 2>/dev/null || true

# Start MongoDB with port exposed
docker run -d \
  --name vc_conformance_mongo \
  --health-cmd="mongosh --eval \"db.adminCommand('ping')\"" \
  --health-interval=10s \
  --health-timeout=5s \
  --health-retries=5 \
  -p 27017:27017 \
  mongo:7.0

# Add to cleanup
CLEANUP_DOCKER="vc_conformance_mongo"

# Wait for MongoDB to be healthy
echo_info "Waiting for MongoDB to be ready..."
for i in {1..30}; do
    if docker exec vc_conformance_mongo mongosh --eval "db.adminCommand('ping')" &>/dev/null; then
        echo_info "MongoDB is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        echo_error "MongoDB failed to become healthy"
        exit 1
    fi
    sleep 1
done

# Initialize MongoDB for verifier-proxy
echo_info "Initializing MongoDB database..."
docker exec vc_conformance_mongo mongosh <<'MONGO_INIT'
use verifier_proxy
db.createCollection("clients")
db.createCollection("sessions")
db.clients.createIndex({ "client_id": 1 }, { unique: true })
db.sessions.createIndex({ "session_id": 1 }, { unique: true })
db.sessions.createIndex({ "access_token": 1 }, { sparse: true })
db.sessions.createIndex({ "authorization_code": 1 }, { sparse: true })
MONGO_INIT

echo_info "✓ MongoDB ready"

# Step 4: Start ngrok tunnel
echo_step "4/8 Starting ngrok tunnel..."

ngrok http 8080 --log=stdout --log-level=info > ngrok.log 2>&1 &
NGROK_PID=$!
CLEANUP_PIDS+=($NGROK_PID)
CLEANUP_FILES+=("ngrok.log")

echo_info "ngrok PID: $NGROK_PID"

# Wait for ngrok to start
echo_info "Waiting for ngrok to initialize..."
for i in {1..20}; do
    if curl -s http://localhost:4040/api/tunnels &>/dev/null; then
        echo_info "ngrok API is responding"
        break
    fi
    if [ $i -eq 20 ]; then
        echo_error "ngrok API failed to start after 20 seconds"
        echo_info "Check if ngrok process is running: ps aux | grep ngrok"
        exit 1
    fi
    sleep 1
done

# Wait a bit more for tunnel to be established
sleep 3

# Get ngrok URL with retry
NGROK_URL=""
for i in {1..5}; do
    NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | jq -r '.tunnels[0].public_url')
    if [ -n "$NGROK_URL" ] && [ "$NGROK_URL" != "null" ]; then
        echo_info "Got ngrok URL on attempt $i"
        break
    fi
    echo_info "Waiting for tunnel to be established (attempt $i/5)..."
    sleep 2
done

if [ -z "$NGROK_URL" ] || [ "$NGROK_URL" == "null" ]; then
    echo_error "Failed to get ngrok URL"
    echo_info "Check ngrok.log for details"
    exit 1
fi

echo_info "✓ ngrok tunnel: $NGROK_URL"

# Step 5: Generate conformance configuration
echo_step "5/8 Generating conformance configuration..."

cat > config.conformance.yaml <<EOF
---
common:
  mongo:
    uri: mongodb://localhost:27017
  production: false
  tracing:
    addr: "localhost:4318"
    type: "none"

verifier_proxy:
  api_server:
    addr: :8080
    tls:
      enabled: false
  external_url: "$NGROK_URL"
  oidc:
    issuer: "$NGROK_URL"
    signing_key_path: "./developer_tools/private_rsa.pem"
    signing_alg: "RS256"
    id_token_duration: 3600
    access_token_duration: 3600
    refresh_token_duration: 86400
    code_duration: 600
    session_duration: 1800
    subject_type: "public"
    subject_salt: "conformance-test-salt-$(date +%s)"
  openid4vp:
    presentation_timeout: 600
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes:
          - "profile"
          - "pid"
      - vct: "urn:eudi:ehic:1"
        scopes:
          - "ehic"
EOF

CLEANUP_FILES+=("config.conformance.yaml")
echo_info "✓ Configuration generated"

# Step 6: Build and start verifier-proxy
echo_step "6/8 Building and starting verifier-proxy..."

# Build the binary
echo_info "Building verifier-proxy binary..."
make build-verifier-proxy > /tmp/build-verifier-proxy.log 2>&1
if [ $? -ne 0 ]; then
    echo_error "Failed to build verifier-proxy"
    tail -20 /tmp/build-verifier-proxy.log
    exit 1
fi
echo_info "✓ Build complete"

# Run the binary
VC_CONFIG_YAML=config.conformance.yaml ./bin/vc_verifier-proxy > verifier-proxy.log 2>&1 &
PROXY_PID=$!
CLEANUP_PIDS+=($PROXY_PID)
CLEANUP_FILES+=("verifier-proxy.log")

echo_info "verifier-proxy PID: $PROXY_PID"

# Wait for service to start
echo_info "Waiting for verifier-proxy to start..."
for i in {1..30}; do
    if curl -sf http://localhost:8080/.well-known/openid-configuration &>/dev/null; then
        break
    fi
    if ! kill -0 $PROXY_PID 2>/dev/null; then
        echo_error "verifier-proxy crashed during startup"
        echo_info "Check verifier-proxy.log for details:"
        tail -30 verifier-proxy.log
        echo ""
        echo_error "Keeping verifier-proxy.log for inspection"
        # Remove from cleanup list
        CLEANUP_FILES=("${CLEANUP_FILES[@]/verifier-proxy.log/}")
        exit 1
    fi
    if [ $i -eq 30 ]; then
        echo_error "verifier-proxy failed to start within 30 seconds"
        echo_info "Last 30 lines of verifier-proxy.log:"
        tail -30 verifier-proxy.log
        echo ""
        echo_error "Keeping verifier-proxy.log for inspection"
        # Remove from cleanup list
        CLEANUP_FILES=("${CLEANUP_FILES[@]/verifier-proxy.log/}")
        exit 1
    fi
    sleep 1
done

echo_info "✓ verifier-proxy running"

# Step 7: Validate endpoints
echo_step "7/8 Validating OIDC endpoints..."

DISCOVERY_URL="$NGROK_URL/.well-known/openid-configuration"

# Test discovery
echo_info "Testing discovery endpoint..."
if ! DISCOVERY=$(curl -sf "$DISCOVERY_URL"); then
    echo_error "Discovery endpoint not accessible"
    exit 1
fi

# Validate discovery response
ISSUER=$(echo "$DISCOVERY" | jq -r '.issuer')
if [ "$ISSUER" != "$NGROK_URL" ]; then
    echo_error "Issuer mismatch: expected $NGROK_URL, got $ISSUER"
    exit 1
fi

echo_info "  ✓ Discovery endpoint"
echo_info "  ✓ Issuer: $ISSUER"

# Test JWKS
JWKS_URI=$(echo "$DISCOVERY" | jq -r '.jwks_uri')
if ! JWKS=$(curl -sf "$JWKS_URI"); then
    echo_error "JWKS endpoint not accessible"
    exit 1
fi

KEY_COUNT=$(echo "$JWKS" | jq '.keys | length')
echo_info "  ✓ JWKS endpoint ($KEY_COUNT keys)"

# Test registration
REG_ENDPOINT=$(echo "$DISCOVERY" | jq -r '.registration_endpoint')
TEST_CLIENT=$(cat <<JSON
{
  "redirect_uris": ["https://example.com/callback"],
  "client_name": "Conformance Test Client",
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
JSON
)

if ! CLIENT_RESP=$(curl -sf -X POST "$REG_ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "$TEST_CLIENT"); then
    echo_error "Registration endpoint failed"
    exit 1
fi

CLIENT_ID=$(echo "$CLIENT_RESP" | jq -r '.client_id')
echo_info "  ✓ Registration endpoint (client_id: ${CLIENT_ID:0:8}...)"

echo_info "✓ All endpoints validated"

# Step 8: Display test instructions
echo_step "8/8 Ready for conformance testing!"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}OpenID Connect Conformance Suite Configuration${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${YELLOW}Issuer Configuration:${NC}"
echo "  Issuer URL:        $NGROK_URL"
echo "  Discovery:         $DISCOVERY_URL"
echo "  Registration:      $REG_ENDPOINT"
echo ""
echo -e "${YELLOW}Conformance Suite Setup:${NC}"
echo "  1. Go to: https://www.certification.openid.net/"
echo "  2. Login and click 'Create a new test plan'"
echo "  3. Select test plan:"
echo "     - For basic testing: 'oidcc-basic-certification-test-plan'"
echo "     - For dynamic reg:   'oidcc-client-test-plan'"
echo "  4. Configure test:"
echo "     Server metadata location: $DISCOVERY_URL"
echo "     Client registration type: Dynamic"
echo "     Response type: code"
echo "     Client auth method: client_secret_basic"
echo ""
echo -e "${YELLOW}Logs (in separate terminals):${NC}"
echo "  tail -f ngrok.log           # ngrok tunnel logs"
echo "  tail -f verifier-proxy.log  # verifier-proxy logs"
echo ""
echo -e "${YELLOW}Test Credentials (pre-registered):${NC}"
echo "  Client ID:     $CLIENT_ID"
echo "  (client_secret in response above)"
echo ""
echo -e "${RED}Press Ctrl+C to stop all services${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Keep script running
echo_info "Services running. Waiting for Ctrl+C..."
wait $PROXY_PID

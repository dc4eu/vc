# OIDC Conformance Testing

This directory contains scripts and documentation for validating the verifier-proxy OIDC Provider implementation against the OpenID Connect Conformance Suite.

## Quick Start

```bash
# Run the full automated setup
./scripts/run-oidc-conformance.sh
```

This will:
1. Check prerequisites (ngrok, jq, docker)
2. Start MongoDB
3. Start ngrok tunnel on port 8080
4. Generate conformance configuration
5. Start verifier-proxy
6. Validate all endpoints
7. Display conformance suite setup instructions

## Automated Testing with Playwright MCP

For browser automation of conformance tests, use the Playwright MCP integration with VS Code:

### Setup

1. **Install Playwright Chrome Extension** in your browser
   - Get it from: https://github.com/microsoft/playwright-mcp

2. **Configure VS Code MCP** by creating `.vscode/mcp.json`:
   ```json
   {
     "servers": {
       "playwright": {
         "type": "stdio",
         "command": "npx",
         "args": ["@playwright/mcp@latest", "--extension"],
         "env": {
           "PLAYWRIGHT_MCP_EXTENSION_TOKEN": "your-token-here"
         }
       }
     }
   }
   ```

3. **Log into the conformance suite** manually at https://www.certification.openid.net/

### Usage

With the MCP server configured, you can use GitHub Copilot Chat in VS Code to:
- Navigate to conformance tests
- Run automated tests that don't require wallet interaction
- Monitor test results
- Extract test data

Example prompts:
- "Navigate to my test plan in the conformance suite"
- "Run the oidcc-registration-sector-uri test"
- "Check the results of the last test"

## Scripts

### 1. `run-oidc-conformance.sh`

**Purpose**: Automated end-to-end setup for conformance testing

**Usage**:
```bash
./scripts/run-oidc-conformance.sh
```

**What it does**:
- ✅ Validates prerequisites
- ✅ Generates RSA signing key (if needed)
- ✅ Starts MongoDB with proper initialization
- ✅ Starts ngrok HTTPS tunnel
- ✅ Generates conformance configuration with ngrok URL
- ✅ Starts verifier-proxy
- ✅ Validates all OIDC endpoints
- ✅ Registers a test client
- ✅ Displays setup instructions for conformance suite

**Cleanup**: Press Ctrl+C to stop all services

### 2. `conformance_validator.py`

**Purpose**: Standalone validation of OIDC endpoints

**Usage**:
```bash
./scripts/conformance_validator.py <ngrok-url>
```

**Example**:
```bash
./scripts/conformance_validator.py https://abc123.ngrok.io
```

**Tests performed**:
1. ✅ Discovery endpoint (`/.well-known/openid-configuration`)
2. ✅ JWKS endpoint validation
3. ✅ Dynamic client registration (RFC 7591)
4. ✅ Registration CRUD operations (RFC 7592)
5. ✅ OpenID Connect metadata compliance

**Output**: Detailed test results with pass/fail status

## Prerequisites

### 1. Install ngrok

**Ubuntu/Debian**:
```bash
curl -s https://ngrok-agent.s3.amazonaws.com/ngrok.asc | \
  sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | \
  sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok
```

**macOS**:
```bash
brew install ngrok/ngrok/ngrok
```

**Authentication** (free account required):
```bash
# Get authtoken from https://dashboard.ngrok.com/get-started/your-authtoken
ngrok config add-authtoken YOUR_AUTH_TOKEN
```

### 2. Install jq

```bash
sudo apt-get install jq
```

### 3. Python 3 (for validator)

Python 3.8+ with `requests` library:
```bash
pip3 install requests
```

## Manual Testing Workflow

If you prefer manual control:

### Step 1: Start MongoDB

```bash
docker-compose up -d mongo mongo-init-verifier-proxy
```

### Step 2: Start ngrok

```bash
ngrok http 8080
```

Copy the HTTPS URL (e.g., `https://abc123.ngrok.io`)

### Step 3: Create conformance config

```bash
cat > config.conformance.yaml <<EOF
common:
  mongo:
    uri: mongodb://localhost:27017

verifier_proxy:
  external_url: "https://abc123.ngrok.io"  # Your ngrok URL
  oidc:
    issuer: "https://abc123.ngrok.io"
    signing_key_path: "./developer_tools/private_rsa.pem"
    subject_type: "public"
EOF
```

### Step 4: Start verifier-proxy

```bash
VC_CONFIG_YAML=config.conformance.yaml go run cmd/verifier-proxy/main.go
```

### Step 5: Validate endpoints

```bash
./scripts/conformance_validator.py https://abc123.ngrok.io
```

### Step 6: Run conformance tests

1. Go to https://www.certification.openid.net/
2. Login and create new test plan
3. Select: **oidcc-basic-certification-test-plan**
4. Configure:
   - **Server discovery**: `https://abc123.ngrok.io/.well-known/openid-configuration`
   - **Client registration**: Dynamic
   - **Response type**: code
   - **Client auth**: client_secret_basic

## OpenID Connect Conformance Suite

### Test Plans Available

1. **Basic OP Tests** (Recommended)
   - Plan: `oidcc-basic-certification-test-plan`
   - Tests: Discovery, JWKS, Authorization, Token, UserInfo

2. **Dynamic Registration**
   - Plan: `oidcc-client-test-plan`
   - Tests: RFC 7591/7592 compliance

3. **RP-Initiated Logout**
   - Plan: `oidcc-rpinitiated-logout-certification-test-plan`
   - Tests: Session management

### Expected Results

✅ **Should Pass**:
- Discovery endpoint validation
- JWKS endpoint validation
- Dynamic client registration (POST /register)
- Client configuration retrieval (GET /register/:id)
- Client update (PUT /register/:id)
- Client deletion (DELETE /register/:id)
- PKCE validation (S256)
- Code replay prevention

⚠️ **May Need Adjustment**:
- Authorization flow (requires wallet integration)
- UserInfo endpoint (depends on VP claims)

## Troubleshooting

### ngrok not found

Install ngrok following prerequisites above.

### Discovery endpoint not accessible

Check that verifier-proxy is running:
```bash
curl http://localhost:8080/.well-known/openid-configuration
```

Check ngrok tunnel:
```bash
curl http://localhost:4040/api/tunnels | jq .
```

### MongoDB connection failed

Ensure MongoDB is running:
```bash
docker-compose ps mongo
```

Initialize database:
```bash
docker-compose up mongo-init-verifier-proxy
```

### RSA key not found

Generate signing key:
```bash
mkdir -p developer_tools
openssl genrsa -out developer_tools/private_rsa.pem 2048
```

### Port 8080 already in use

Check what's using port 8080:
```bash
sudo lsof -i :8080
```

Stop the process or change the port in configuration.

## Logs

When running automated script, logs are saved to:
- `ngrok.log` - ngrok tunnel logs
- `verifier-proxy.log` - verifier-proxy service logs

Tail logs in real-time:
```bash
tail -f ngrok.log
tail -f verifier-proxy.log
```

## Test Automation

### Fully Automated Tests

The following tests can run without user interaction:

- ✅ **oidcc-discovery-endpoint-verification** - Discovery metadata validation
- ✅ **oidcc-registration-sector-uri** - Sector identifier URI validation
- ✅ **oidcc-redirect-uri-regfrag** - Registration endpoint validation (error cases)
- ✅ **oidcc-registration-sector-bad** - Registration endpoint validation (error cases)

### Tests Requiring User Authentication

Most authorization flow tests require manual wallet/user authentication:

- ⚠️ **oidcc-server** - Basic authorization flows
- ⚠️ **oidcc-idtoken-rs256** - ID token validation
- ⚠️ **oidcc-userinfo-get** - UserInfo endpoint
- ⚠️ All prompt/scope/claims tests

For these tests, the Playwright MCP automation can:
- Navigate to tests
- Click "Proceed with test" buttons
- Monitor test progress
- But manual authentication is still required

### Test Client Credentials

The conformance suite creates clients dynamically via the registration endpoint. Ensure dynamic registration is working properly by running the validator:

```bash
./scripts/conformance_validator.py https://your-ngrok-url.ngrok.io
```

## References

- [OpenID Connect Certification](https://openid.net/certification/)
- [Conformance Suite](https://www.certification.openid.net/)
- [Testing Guide](https://openid.net/certification/testing/)
- [RFC 7591 - Dynamic Registration](https://tools.ietf.org/html/rfc7591)
- [RFC 7592 - Registration Management](https://tools.ietf.org/html/rfc7592)
- [Playwright MCP](https://github.com/microsoft/playwright-mcp)

## Files

- `run-oidc-conformance.sh` - Main conformance environment setup script
- `conformance_validator.py` - Standalone endpoint validation tool
- `README-conformance.md` - This documentation file


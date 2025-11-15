#!/bin/bash
#
# Complete Bootstrap Script for Verifier Proxy
# Runs all initialization steps
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "============================================"
echo "  Verifier Proxy Complete Bootstrap"
echo "============================================"
echo ""

# 1. Initialize MongoDB (indexes)
echo "Step 1: Initializing MongoDB..."
bash "$SCRIPT_DIR/init_mongodb.sh"
echo ""

# 2. Register sample clients
echo "Step 2: Registering sample clients..."
bash "$SCRIPT_DIR/register_clients.sh"
echo ""

echo "============================================"
echo "  Bootstrap Complete!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Start the verifier-proxy service"
echo "  2. Configure your RP (Keycloak) with one of the client IDs"
echo "  3. Test the authorization flow"
echo ""
echo "Documentation: docs/verifier-proxy/README.md"

#!/bin/bash
# Generate W3C test suite localConfig.cjs
# Usage: ./scripts/gen-w3c-config.sh <port> <output_file>

PORT=${1:-8888}
OUTPUT_FILE=${2:-/tmp/w3c-test-suite/localConfig.cjs}

cat > "$OUTPUT_FILE" << EOF
/**
 * W3C VC Data Model 2.0 Test Suite Configuration
 *
 * Generated configuration for local testing
 * Server running on port $PORT
 */

const SERVER_URL = 'http://localhost:$PORT';

module.exports = {
  settings: {
    enableInteropTests: false,
    testAllImplementations: false,
    tags: ['vc2.0'],
  },
  implementations: [
    {
      name: 'DC4EU',
      implementation: 'vc20-multi-suite',
      issuers: [
        {
          id: 'urn:dc4eu:issuer:ecdsa-rdfc',
          endpoint: \`\${SERVER_URL}/credentials/issue\`,
          tags: ['vc2.0', 'ecdsa-rdfc-2019', 'ecdsa-sd-2023'],
          supportedContexts: [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
        }
      ],
      verifiers: [
        {
          id: 'urn:dc4eu:verifier:ecdsa-sd',
          endpoint: \`\${SERVER_URL}/credentials/verify\`,
          tags: ['vc2.0', 'ecdsa-sd-2023'],
          supportedContexts: [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
        },
        {
          id: 'urn:dc4eu:verifier:ecdsa-rdfc',
          endpoint: \`\${SERVER_URL}/credentials/verify\`,
          tags: ['vc2.0', 'ecdsa-rdfc-2019'],
          supportedContexts: [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
        }
      ],
      vpVerifiers: [
        {
          id: 'urn:dc4eu:vp-verifier:ecdsa-sd',
          endpoint: \`\${SERVER_URL}/presentations/verify\`,
          tags: ['vc2.0', 'ecdsa-sd-2023'],
          supportedContexts: [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          supportsChallenge: true,
          supportsDomain: true
        },
        {
          id: 'urn:dc4eu:vp-verifier:ecdsa-rdfc',
          endpoint: \`\${SERVER_URL}/presentations/verify\`,
          tags: ['vc2.0', 'ecdsa-rdfc-2019'],
          supportedContexts: [
            'https://www.w3.org/ns/credentials/v2',
            'https://www.w3.org/ns/credentials/examples/v2'
          ],
          supportsChallenge: true,
          supportsDomain: true
        }
      ]
    }
  ]
};
EOF

echo "Generated $OUTPUT_FILE for port $PORT"

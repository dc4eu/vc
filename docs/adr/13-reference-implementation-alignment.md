# Align with Digital Bazaar Reference Implementation for Cryptosuites

## Status

Accepted

## Context

The W3C Verifiable Credentials Data Integrity specifications are complex and contain subtle requirements that can be interpreted differently. During ECDSA-SD-2023 implementation, we encountered:

1. **Ambiguous spec language** around mandatory N-Quad selection
2. **Edge cases not covered by test vectors** (e.g., type quad inclusion)
3. **Implementation-specific choices** (e.g., HMAC blank node label format)

Digital Bazaar maintains the reference implementations for VC Data Integrity:
- `@digitalbazaar/di-sd-primitives` - Core selective disclosure primitives
- `@digitalbazaar/ecdsa-sd-2023-cryptosuite` - ECDSA-SD-2023 implementation
- `@digitalbazaar/data-integrity` - General Data Integrity proof handling

These libraries are used by many production issuers and are the de facto standard for interoperability.

## Decision

When implementing cryptographic suites, we MUST:

1. **Use Digital Bazaar implementations as reference** for spec interpretation
2. **Create JavaScript debug scripts** to extract intermediate values from reference implementation:
   - Proof hash
   - Mandatory hash
   - HMAC-transformed blank node labels
   - Combined signing data
3. **Compare Go implementation outputs** against reference at each step
4. **Document any intentional deviations** with rationale

### Debug Script Pattern

```javascript
// Example: verify-debug.mjs
import * as diSdPrimitives from '@digitalbazaar/di-sd-primitives';
// ... extract and log intermediate values for comparison
```

### Go Test Pattern

```go
// Log intermediate values for comparison with reference
t.Logf("Mandatory Hash: %s", hex.EncodeToString(mandatoryHash[:]))
t.Logf("Expected (from JS): %s", expectedMandatoryHash)
```

## Consequences

### Positive

- Guaranteed interoperability with production issuers
- Clear disambiguation of spec ambiguities
- Faster debugging of verification failures
- Confidence in spec compliance

### Negative

- Dependency on external JavaScript tooling for debugging
- Need to track Digital Bazaar library updates
- May inherit any bugs from reference (rare, well-tested)

## Implementation Notes

Key packages for reference:
- `di-sd-primitives@3.0.0` - `createInitialSelection`, `canonicalizeAndGroup`
- `ecdsa-sd-2023-cryptosuite@3.4.0` - Proof creation/verification
- `jsonld@8.x` - JSON-LD processing

Debug scripts location: `testdata/` or `debug-*/` directories (not committed if containing credentials)

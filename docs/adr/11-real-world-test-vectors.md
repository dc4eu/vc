# Real-World Test Vectors Required for Cryptosuite Validation

## Status

Accepted

## Context

Our ECDSA-SD-2023 implementation passed all 59 W3C conformance test vectors but failed to verify real-world credentials from Singapore Academy of Law (SAL). This exposed a gap in our testing strategy.

W3C test vectors are designed to test specific features in isolation and may not exercise all code paths that real-world implementations encounter. The SAL eApostille credentials:

1. Use BASE proofs (CBOR tag `0xd95d00`) presented directly, not derived proofs
2. Have complex credential structures with nested objects and status lists
3. Use specific mandatory pointer configurations (`/issuer`, `/validFrom`)
4. Were signed by the Digital Bazaar reference implementation

The subtle W3C spec requirement about including type quads in mandatory selection (Section 3.4.11) was not caught by synthetic test vectors because they may have:
- Used credentials where type quads were already implicitly included
- Not tested the exact mandatory pointer combinations that exposed the bug

## Decision

For any cryptographic suite implementation:

1. **W3C test vectors are necessary but not sufficient** - They establish baseline conformance but don't guarantee real-world interoperability

2. **Collect real-world test vectors** from production issuers using the target cryptosuite:
   - Singapore SAL eApostille (`ecdsa-sd-2023` BASE proofs)
   - Other government/enterprise issuers as available

3. **Store test vectors in `testdata/` directories** organized by source:
   - `testdata/w3c-test-vectors/` - Official W3C conformance tests
   - `testdata/sg-test-vectors/` - Singapore SAL credentials
   - `testdata/<source>-test-vectors/` - Other real-world sources

4. **Create integration tests** that verify against real-world test vectors, with detailed debug output for hash comparisons

5. **Document issuer public keys and DID resolution** for offline testing

## Consequences

### Positive

- Higher confidence in real-world interoperability
- Earlier detection of spec interpretation issues
- Better alignment with reference implementations (Digital Bazaar)
- Comprehensive test coverage across implementation variations

### Negative

- More test data to maintain
- Need to track issuer key rotations
- Potential privacy considerations for test credentials (use synthetic data where possible)

## Implementation

Test files created:
- `pkg/vc20/crypto/ecdsa/sd_eapostille_test.go` - SAL eApostille verification tests
- `testdata/sg-test-vectors/` - Singapore test credentials

Required test assertions:
1. Mandatory hash matches reference implementation
2. Proof hash matches reference implementation
3. Full signature verification succeeds

# Support ECDSA-SD-2023 BASE Proof Verification

## Status

Accepted

## Context

The ECDSA-SD-2023 specification defines two proof types:

1. **BASE proofs** (CBOR tag `0xd95d00` / 23808) - Created by the issuer, contain:
   - Base signature (64 bytes for P-256)
   - Ephemeral public key (35 bytes multicodec-compressed)
   - HMAC key (32 bytes)
   - Per-message signatures for non-mandatory quads
   - Mandatory JSON pointers

2. **DERIVED proofs** (CBOR tag `0xd95d01` / 23809) - Created by the holder for selective disclosure

The typical flow is: Issuer creates BASE → Holder creates DERIVED → Verifier verifies DERIVED.

However, real-world usage (e.g., Singapore SAL eApostille) shows that **BASE proofs may be presented directly** without derivation. This occurs when:
- Full credential disclosure is acceptable
- The holder system doesn't implement derivation
- The credential is verified at the point of issuance

Our initial implementation only supported DERIVED proof verification, causing BASE proofs to fail.

## Decision

The verifier MUST support verification of both BASE and DERIVED proofs:

### BASE Proof Verification (Section 3.6.2)

1. Decode CBOR with tag `0xd95d00`
2. Extract: baseSignature, ephemeralPublicKey, hmacKey, signatures, mandatoryPointers
3. Compute proofHash from canonicalized proof options
4. Select mandatory N-Quads using pointers (including type quads per ADR-10)
5. Compute mandatoryHash from selected quads
6. Build combined data: `proofHash || ephemeralPublicKey || mandatoryHash`
7. Verify baseSignature against SHA-256(combined) using issuer's public key

### DERIVED Proof Verification (Section 3.6.4)

1. Decode CBOR with tag `0xd95d01`
2. Follow the selective disclosure verification algorithm
3. Verify disclosed claims against holder's presentation

### Detection Logic

```go
if len(proofBytes) >= 3 && proofBytes[0] == 0xd9 && proofBytes[1] == 0x5d {
    switch proofBytes[2] {
    case 0x00:
        return verifyBaseProof(...)
    case 0x01:
        return verifyDerivedProof(...)
    }
}
```

## Consequences

### Positive

- Full interoperability with issuers presenting BASE proofs directly
- SAL eApostille credentials verify correctly
- Flexible deployment options for holders

### Negative

- More complex verification logic
- Need to maintain two verification code paths
- BASE proofs reveal full credential (no selective disclosure)

## References

- W3C VC-DI-ECDSA Section 3.5.2: serializeBaseProofValue
- W3C VC-DI-ECDSA Section 3.5.7: serializeDerivedProofValue
- W3C VC-DI-ECDSA Section 3.6.2: Base Proof Verification

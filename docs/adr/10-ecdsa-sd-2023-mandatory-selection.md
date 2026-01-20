# ECDSA-SD-2023 Mandatory N-Quad Selection Must Include Type Quads

## Status

Accepted

## Context

During verification of Singapore Academy of Law (SAL) eApostille credentials using the `ecdsa-sd-2023` cryptosuite, we discovered that our implementation failed to verify real-world credentials despite passing all 59 W3C test vectors.

Root cause analysis revealed a hash mismatch in the mandatory N-Quad selection. The W3C VC-DI-ECDSA specification Section 3.4.11 `createInitialSelection` states:

> "The selection MUST include all `type`s in the path of any JSON Pointer, including any root document `type`."

Our initial implementation selected only the N-Quads directly referenced by mandatory pointers (e.g., `/issuer`, `/validFrom`) but omitted the root document's `rdf:type` quad(s). This subtle requirement is not explicitly tested by the W3C test vectors but is essential for interoperability with the Digital Bazaar reference implementation (`di-sd-primitives`).

### Evidence

For mandatory pointers `["/issuer", "/validFrom"]`:
- **Before fix**: 2 quads selected (issuer + validFrom)
- **After fix**: 3 quads selected (type + issuer + validFrom)
- **Mandatory hash before**: `3b3fe231696b24aa21040236152782195736921af2bc49055f39ed78cbdc5ffe`
- **Mandatory hash after**: `aef02d63b87de37d247648f1027f4cc8d6e7a709c76dd9b854689abaeff0d8a9` (matches reference)

## Decision

The `selectMandatoryNQuads` function in `pkg/vc20/crypto/ecdsa/sd_helpers.go` MUST:

1. Track which container paths are touched by mandatory pointers
2. Include the `rdf:type` quad(s) for each container in the path, including the root document
3. For any pointer touching the root level (e.g., `/issuer`), include the root document's type quad(s)

## Consequences

### Positive

- Interoperability with Digital Bazaar reference implementation
- SAL eApostille and other real-world credentials now verify correctly
- Full compliance with W3C VC-DI-ECDSA specification Section 3.4.11
- All existing W3C test vectors continue to pass

### Negative

- More complex mandatory selection logic
- Requires careful reading of W3C spec for future cryptosuite implementations

## References

- W3C VC-DI-ECDSA Specification: https://www.w3.org/TR/vc-di-ecdsa/
- Section 3.4.11 createInitialSelection
- Digital Bazaar di-sd-primitives: https://github.com/digitalbazaar/di-sd-primitives

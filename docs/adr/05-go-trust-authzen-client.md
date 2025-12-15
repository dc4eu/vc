# Use go-trust authzenclient for key resolution

## Status

Proposed

## Context

The vc project currently has its own implementation of an AuthZEN client in `pkg/authzen/client.go` and key resolution in `pkg/keyresolver/`. The go-trust project at github.com/SUNET/go-trust now provides a general-purpose authzenclient package that supports:

- Full DID discovery via `.well-known/authzen-configuration`
- Trust evaluation requests (`/evaluation` endpoint)
- Resolution-only requests for DID/metadata resolution
- Configurable HTTP transport with timeouts
- Support for both JWK and X.509 certificate chain validation

This aligns with ADR-01 (Cryptographic libraries) which states that we should "avoid implementing cryptographic primitives, favouring the reuse of existing, well-tested libraries."

## Decision

Replace the local `pkg/authzen/client.go` implementation with the go-trust `authzenclient` package for non-local key resolution in the vc20 implementation.

## Consequences

### Positive

- Reduced code maintenance burden
- Benefit from upstream improvements to DID resolution
- Consistent with ADR-01 philosophy
- Full discovery support via `.well-known/authzen-configuration`
- Better tested code (go-trust has comprehensive test coverage)

### Negative

- External dependency on go-trust project
- May need to adapt existing keyresolver interfaces

## Implementation Plan

1. Add `github.com/SUNET/go-trust` as a dependency
2. Create an adapter in `pkg/keyresolver/` that wraps go-trust's authzenclient
3. Update vc20 crypto suites to use the new resolver for non-local keys
4. Remove or deprecate `pkg/authzen/client.go`
5. Ensure >70% test coverage per ADR-02

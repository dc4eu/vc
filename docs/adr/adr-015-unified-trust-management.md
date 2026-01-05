# ADR-15: Unified Trust Management Across Credential Formats

## Status

Accepted

## Context

The VC implementation supports multiple credential formats:
- **SD-JWT VC** (IETF draft): Uses JWTs with optional x5c certificate chains
- **ISO mDOC** (ISO/IEC 18013-5): Uses COSE with IACA certificate chains
- **W3C VC 2.0** (with ECDSA-SD-2023): Uses DIDs for key identification

Each format traditionally uses different mechanisms for trust:
- SD-JWT: x5c header contains certificate chain, issuer is URL-based
- mDOC: IACA (Issuing Authority CA) certificates, country-based issuers
- VC 2.0: DID-based key resolution and trust frameworks

The go-trust library provides a unified AuthZEN-based protocol for trust evaluation that supports:
- `EvaluateJWK`: Validate a JWK is trusted for a given subject
- `EvaluateX5C`: Validate an x5c certificate chain is trusted for a given subject
- `Resolve`: Resolve a DID to its key material

The key insight is that while DID resolution (name→key) is only applicable to VC 2.0, trust validation (is this name-to-key binding trusted?) applies to all formats.

## Decision

We introduce a unified trust management layer via `pkg/trust` that can be used consistently across all credential formats:

### Core Interface

```go
type TrustEvaluator interface {
    Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)
    SupportsKeyType(keyType KeyType) bool
}

type EvaluationRequest struct {
    SubjectID string    // Identifier (issuer URL, DID, country code)
    KeyType   KeyType   // "jwk" or "x5c"
    Key       any       // *ecdsa.PublicKey, JWK map, or []*x509.Certificate
    Role      Role      // "issuer", "verifier", etc.
}
```

### Implementations

1. **GoTrustEvaluator** (`gotrust.go`): Uses go-trust AuthZEN client
   - Calls `EvaluateX5C` for certificate chains
   - Calls `EvaluateJWK` for JWK keys
   - Also provides `ResolveKey` for DID resolution

2. **LocalTrustEvaluator** (`local.go`): Offline trust validation
   - Validates x5c chains against local certificate pool
   - Supports role restrictions and custom verification

3. **CompositeEvaluator** (`composite.go`): Combines multiple strategies
   - `FirstSuccess`: Accept if any evaluator trusts
   - `AllMustSucceed`: All evaluators must trust
   - `Fallback`: Use first available result

### Integration Points

**SD-JWT VC** (`pkg/sdjwtvc/verification.go`):
```go
type VerificationOptions struct {
    // ... existing fields ...
    TrustEvaluator trust.TrustEvaluator  // Optional trust evaluator
    TrustContext   context.Context       // Context for trust calls
}
```

When `TrustEvaluator` is set and x5c header is present:
1. Parse x5c certificate chain from JWT header
2. Extract issuer ID (from `iss` claim or certificate CN)
3. Call `TrustEvaluator.Evaluate()` with `KeyTypeX5C`
4. If trusted, use certificate's public key for signature verification

**ISO mDOC** (`pkg/mdoc/verifier.go`):
```go
type VerifierConfig struct {
    TrustList      *IACATrustList       // Local IACA trust (optional)
    TrustEvaluator trust.TrustEvaluator // External trust evaluator (optional)
    // ...
}
```

When `TrustEvaluator` is set:
1. Extract certificate chain from COSE_Sign1
2. Extract issuer ID from DS certificate (Organization, Country, or CN)
3. Call `TrustEvaluator.Evaluate()` with `KeyTypeX5C`
4. Skip local `IACATrustList` verification if evaluator approves

### Usage Patterns

**Remote Trust Only (go-trust)**:
```go
evaluator := trust.NewGoTrustEvaluator(trust.GoTrustConfig{
    BaseURL: "https://trust.example.com",
})

// SD-JWT
result, err := client.ParseAndVerify(sdJWT, nil, &VerificationOptions{
    TrustEvaluator: evaluator,
})

// mDOC
verifier, _ := NewVerifier(VerifierConfig{
    TrustEvaluator: evaluator,
})
```

**Local Trust Only**:
```go
evaluator := trust.NewLocalTrustEvaluator(trust.LocalTrustConfig{
    TrustedRoots: []*x509.Certificate{rootCA},
})

// mDOC - can also use IACATrustList directly
verifier, _ := NewVerifier(VerifierConfig{
    TrustList: iacaTrustList,
})
```

**Hybrid (Local + Remote Fallback)**:
```go
composite := trust.NewCompositeEvaluator(
    trust.StrategyFirstSuccess,
    localEvaluator,
    goTrustEvaluator,
)
```

## Consequences

### Positive

- **Consistent API**: All credential formats use the same `TrustEvaluator` interface
- **Flexible Deployment**: Supports offline, online, and hybrid trust models
- **go-trust Integration**: Leverages existing AuthZEN protocol implementation
- **Backward Compatible**: Existing code using direct public keys or `IACATrustList` continues to work

### Negative

- **Additional Abstraction**: One more layer between credentials and trust decisions
- **Context Propagation**: Async trust evaluation requires context handling

### Neutral

- **Key Type Distinction**: `KeyTypeJWK` vs `KeyTypeX5C` makes it explicit which validation path is used
- **Role Support**: Role-based trust decisions can be enforced at evaluation time

## Related ADRs

- **ADR-14**: Trusted Authorities Support (W3C VC 2.0 with DIDs)
- This ADR extends trust management to non-DID credential formats

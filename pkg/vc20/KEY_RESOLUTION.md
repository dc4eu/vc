# Key Resolution Strategy for VC 2.0

## Current State
- `pkg/keyresolver` exists but is currently unused by `pkg/vc20`.
- `pkg/vc20` crypto suites (e.g., `eddsa-rdfc-2022`, `ecdsa-rdfc-2019`) currently require the caller to pass the raw `ed25519.PublicKey` or `ecdsa.PublicKey` to the `Verify` method.
- The caller is responsible for resolving the `verificationMethod` (DID) to a public key before verification.

## Objective
- Support `did:key` and `multikey` resolution locally within the library (using `pkg/keyresolver` logic) to avoid unnecessary network calls.
- Support other DID methods (e.g., `did:web`, `did:ebsi`) via an external Universal Resolver service (or similar DID resolution service).
- Provide a unified interface for key resolution during credential verification.

## Implementation Plan

### 1. Enhance `pkg/keyresolver`
- **`LocalResolver`**: Ensure it fully supports `did:key` and `multikey` (already partially implemented).
- **`HTTPResolver`**: Create a new resolver implementation that queries an external Universal Resolver (e.g., `https://dev.uniresolver.io/1.0/identifiers/{did}`).
  - Should support caching.
  - Should parse the DID Document to find the Verification Method and extract the public key (JWK or Multibase).
- **`MultiResolver`**: Use the existing `MultiResolver` to chain them:
  1. Try `LocalResolver` first.
  2. Fallback to `HTTPResolver`.

### 2. Integrate with `pkg/vc20`
- Update `Suite` interfaces in `pkg/vc20/crypto` to accept a `keyresolver.Resolver` instead of (or in addition to) a raw key.
- Alternatively, provide a higher-level `Verifier` struct in `pkg/vc20` that manages the `Resolver` and delegates to the appropriate crypto suite.

#### Example Verifier Structure
```go
type Verifier struct {
    Resolver keyresolver.Resolver
    Suites   map[string]CryptoSuite
}

func (v *Verifier) VerifyCredential(cred *credential.RDFCredential) error {
    // 1. Extract proof from credential
    // 2. Get verificationMethod (DID URL) from proof
    // 3. Resolve key: key, err := v.Resolver.Resolve(vm)
    // 4. Select suite based on 'cryptosuite' property in proof
    // 5. Verify: suite.Verify(cred, key)
}
```

### 3. Trust Model
- Key resolution only retrieves the cryptographic key associated with the DID.
- Trust evaluation (e.g., "Is this DID authorized to issue this type of credential?") is a separate layer.
- This can be handled by `pkg/authzen` or the `TrustEvaluator` interface in `pkg/keyresolver`.

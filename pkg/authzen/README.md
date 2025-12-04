# AuthZEN Trust Protocol Client

This package implements a client for [draft-johansson-authzen-trust](https://leifj.github.io/draft-johansson-authzen-trust/draft-johansson-authzen-trust.html), an AuthZEN profile for trust registries.

## Overview

The AuthZEN Trust protocol provides **trust evaluation** for name-to-key bindings. It does NOT resolve keys from identifiers - instead, it validates whether a given public key is authorized to be bound to a given name (subject ID).

## Protocol Summary

- **Endpoint**: `POST /evaluation`
- **Purpose**: Validate that a public key is bound to a name and optionally authorized for a specific role
- **Request**: Contains subject (name), resource (public key), and optional action (role)
- **Response**: `{"decision": true/false}`

## Usage Examples

### Basic Trust Evaluation with JWK

```go
import "vc/pkg/authzen"

// Create client
client := authzen.NewClient("https://trust-registry.example.com")

// Create a JWK from Ed25519 public key
jwk := authzen.JWKFromEd25519(publicKeyBytes)

// Evaluate if the key is bound to the subject
trusted, err := client.EvaluateJWK("did:example:123", jwk, "")
if err != nil {
    // Handle error
}

if trusted {
    // Key is authorized for this subject
}
```

### Trust Evaluation with Role

```go
// Check if a wallet provider certificate is authorized
certChain := []string{
    "MIICx...", // base64-encoded X.509 cert
    "MIIBy...", // intermediate cert
}

trusted, err := client.EvaluateX5C(
    "did:foo:wallet-provider",
    certChain,
    "http://ec.europa.eu/NS/wallet-provider",
)
```

### Integration with Key Resolution

The AuthZEN client is typically used as a **trust validation layer** after key resolution:

```go
import (
    "vc/pkg/keyresolver"
    "vc/pkg/authzen"
)

// 1. Resolve the key from verification method
localResolver := keyresolver.NewLocalResolver()
publicKey, err := localResolver.ResolveEd25519("did:key:u...")

// 2. Evaluate trust in the resolved key
trustEvaluator := keyresolver.NewAuthZENTrustEvaluator("https://trust-registry.example.com")
trusted, err := trustEvaluator.EvaluateTrust("did:key:u...", publicKey, "issuer")

// OR use ValidatingResolver to combine both steps
validatingResolver := keyresolver.NewValidatingResolver(
    localResolver,
    trustEvaluator,
    "issuer", // required role
)
publicKey, err := validatingResolver.ResolveEd25519("did:key:u...")
// This returns the key only if it resolves AND is trusted
```

## Request Format

According to the specification:

```json
{
  "type": "authzen",
  "request": {
    "subject": {
      "type": "key",
      "id": "did:example:123"
    },
    "resource": {
      "type": "jwk",
      "id": "did:example:123",
      "key": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "..."
      }
    },
    "action": {
      "name": "issuer"
    }
  }
}
```

## Response Format

```json
{
  "decision": true
}
```

Or with error context:

```json
{
  "decision": false,
  "context": {
    "reason": {
      "403": "Unknown service"
    }
  }
}
```

## Supported Key Types

- **JWK** (`type: "jwk"`): JSON Web Key format (Ed25519, etc.)
- **X5C** (`type: "x5c"`): X.509 certificate chains

## Helper Functions

### JWKFromEd25519

Convert Ed25519 public key bytes to JWK format:

```go
jwk := authzen.JWKFromEd25519(publicKey) // 32 bytes
// Returns: {"kty": "OKP", "crv": "Ed25519", "x": "..."}
```

### Ed25519FromJWK

Extract Ed25519 public key from JWK:

```go
publicKey, err := authzen.Ed25519FromJWK(jwk)
// Returns: 32-byte Ed25519 public key
```

## Architecture

This package is designed to be used with `pkg/keyresolver` but is completely independent. It can be used in any context where trust evaluation for name-to-key bindings is needed.

The protocol is based on the AuthZEN authorization framework but specialized for trust registries, supporting various trust registry types:

- ETSI trust status lists
- OpenID Federation
- Ledgers
- Custom trust registries

## Security Considerations

- The protocol is meant for use within a common security domain
- May be deployed without authentication on localhost
- OAuth 2.0 authentication can be implemented for production deployments
- Trust registries should validate certificate chains and check revocation status

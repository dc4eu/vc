# Go-Trust AuthZEN Client Integration Plan

This document outlines the detailed implementation plan for replacing the local authzen client with go-trust's `authzenclient` package.

## Current State

### Local Implementation

```
pkg/authzen/
├── client.go          # Basic AuthZEN client (~200 lines)
└── README.md

pkg/keyresolver/
├── resolver.go        # Key resolution interfaces and local resolver
└── authzen.go         # AuthZEN trust evaluator wrapper
```

### Go-Trust Implementation

```
github.com/SUNET/go-trust/pkg/
├── authzen/           # AuthZEN types (Subject, Resource, Action, etc.)
└── authzenclient/     # Full-featured client
    ├── client.go      # Client with discovery, evaluation, resolution
    └── client_test.go # Comprehensive tests
```

## Feature Comparison

| Feature | Local | go-trust |
|---------|-------|----------|
| Basic evaluation | ✓ | ✓ |
| JWK evaluation | ✓ | ✓ |
| X.509 evaluation | ✓ | ✓ |
| Discovery (`.well-known`) | ✗ | ✓ |
| Resolution-only requests | ✗ | ✓ |
| Configurable timeouts | Limited | ✓ |
| Context support | ✗ | ✓ |
| Request validation | ✗ | ✓ |
| Error typing | Basic | ✓ |

## Implementation Steps

### Step 1: Add go-trust Dependency

```bash
go get github.com/SUNET/go-trust@latest
go mod vendor
```

### Step 2: Create Adapter Interface

Create `pkg/keyresolver/gotrust_adapter.go`:

```go
//go:build vc20

package keyresolver

import (
    "context"
    "crypto/ed25519"
    "crypto/ecdsa"
    "fmt"

    "github.com/SUNET/go-trust/pkg/authzen"
    "github.com/SUNET/go-trust/pkg/authzenclient"
)

// GoTrustResolver uses go-trust authzenclient for key resolution
type GoTrustResolver struct {
    client *authzenclient.Client
}

// NewGoTrustResolver creates a resolver using go-trust
func NewGoTrustResolver(baseURL string) (*GoTrustResolver, error) {
    client := authzenclient.New(baseURL)
    return &GoTrustResolver{client: client}, nil
}

// NewGoTrustResolverWithDiscovery creates a resolver using discovery
func NewGoTrustResolverWithDiscovery(ctx context.Context, baseURL string) (*GoTrustResolver, error) {
    client, err := authzenclient.Discover(ctx, baseURL)
    if err != nil {
        return nil, fmt.Errorf("discovery failed: %w", err)
    }
    return &GoTrustResolver{client: client}, nil
}

// ResolveEd25519 resolves an Ed25519 key via go-trust
func (g *GoTrustResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
    ctx := context.Background()
    
    // Use resolution-only request to get DID document
    resp, err := g.client.Resolve(ctx, verificationMethod)
    if err != nil {
        return nil, fmt.Errorf("resolution failed: %w", err)
    }
    
    if !resp.Decision {
        return nil, fmt.Errorf("resolution denied for %s", verificationMethod)
    }
    
    // Extract key from trust_metadata (DID document)
    return extractEd25519FromMetadata(resp.Context.TrustMetadata, verificationMethod)
}

// ResolveECDSA resolves an ECDSA key via go-trust  
func (g *GoTrustResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
    ctx := context.Background()
    
    resp, err := g.client.Resolve(ctx, verificationMethod)
    if err != nil {
        return nil, fmt.Errorf("resolution failed: %w", err)
    }
    
    if !resp.Decision {
        return nil, fmt.Errorf("resolution denied for %s", verificationMethod)
    }
    
    return extractECDSAFromMetadata(resp.Context.TrustMetadata, verificationMethod)
}

// EvaluateTrust validates a key binding via go-trust
func (g *GoTrustResolver) EvaluateTrust(ctx context.Context, subjectID string, jwk map[string]any, role string) (bool, error) {
    var action *authzen.Action
    if role != "" {
        action = &authzen.Action{Name: role}
    }
    
    resp, err := g.client.EvaluateJWK(ctx, subjectID, jwk, action)
    if err != nil {
        return false, err
    }
    
    return resp.Decision, nil
}
```

### Step 3: Add ECDSA Support to Resolver Interface

Update `pkg/keyresolver/resolver.go` to support ECDSA:

```go
// Resolver provides methods to resolve public keys from verification methods
type Resolver interface {
    // ResolveEd25519 resolves an Ed25519 public key
    ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error)
    
    // ResolveECDSA resolves an ECDSA public key (P-256, P-384)
    ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error)
}
```

### Step 4: Update VC20 Crypto Suites

Update `pkg/vc20/crypto/eddsa/suite.go` to use resolver:

```go
type Suite struct {
    resolver keyresolver.Resolver
}

func NewSuiteWithResolver(resolver keyresolver.Resolver) *Suite {
    return &Suite{resolver: resolver}
}

func (s *Suite) Verify(cred *credential.RDFCredential, publicKey ed25519.PublicKey) error {
    // If no key provided, try to resolve from verification method
    if publicKey == nil && s.resolver != nil {
        vm := cred.GetVerificationMethod()
        var err error
        publicKey, err = s.resolver.ResolveEd25519(vm)
        if err != nil {
            return fmt.Errorf("failed to resolve key: %w", err)
        }
    }
    // ... existing verification logic
}
```

### Step 5: Helper Functions for Key Extraction

Create `pkg/keyresolver/did_helpers.go`:

```go
//go:build vc20

package keyresolver

import (
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/elliptic"
    "encoding/base64"
    "fmt"
    "math/big"
)

// extractEd25519FromMetadata extracts Ed25519 key from DID document
func extractEd25519FromMetadata(metadata any, verificationMethod string) (ed25519.PublicKey, error) {
    doc, ok := metadata.(map[string]any)
    if !ok {
        return nil, fmt.Errorf("invalid DID document format")
    }
    
    // Find verification method in document
    vms, _ := doc["verificationMethod"].([]any)
    for _, vm := range vms {
        vmMap, ok := vm.(map[string]any)
        if !ok {
            continue
        }
        
        vmID, _ := vmMap["id"].(string)
        if vmID != verificationMethod {
            continue
        }
        
        // Handle publicKeyMultibase
        if multibase, ok := vmMap["publicKeyMultibase"].(string); ok {
            return decodeMultikeyEd25519(multibase)
        }
        
        // Handle publicKeyJwk
        if jwk, ok := vmMap["publicKeyJwk"].(map[string]any); ok {
            return jwkToEd25519(jwk)
        }
    }
    
    return nil, fmt.Errorf("verification method not found: %s", verificationMethod)
}

// extractECDSAFromMetadata extracts ECDSA key from DID document
func extractECDSAFromMetadata(metadata any, verificationMethod string) (*ecdsa.PublicKey, error) {
    // Similar to Ed25519 but handles P-256/P-384 curves
    // ...
}

func jwkToEd25519(jwk map[string]any) (ed25519.PublicKey, error) {
    kty, _ := jwk["kty"].(string)
    if kty != "OKP" {
        return nil, fmt.Errorf("expected OKP key type, got %s", kty)
    }
    
    crv, _ := jwk["crv"].(string)
    if crv != "Ed25519" {
        return nil, fmt.Errorf("expected Ed25519 curve, got %s", crv)
    }
    
    x, _ := jwk["x"].(string)
    pubBytes, err := base64.RawURLEncoding.DecodeString(x)
    if err != nil {
        return nil, err
    }
    
    if len(pubBytes) != ed25519.PublicKeySize {
        return nil, fmt.Errorf("invalid key size: %d", len(pubBytes))
    }
    
    return ed25519.PublicKey(pubBytes), nil
}
```

### Step 6: Update Configuration

Add trust registry configuration to `pkg/model/config.go`:

```go
type TrustRegistry struct {
    // BaseURL is the AuthZEN PDP server URL
    BaseURL string `yaml:"base_url"`
    
    // UseDiscovery enables .well-known discovery
    UseDiscovery bool `yaml:"use_discovery"`
    
    // Timeout in seconds
    Timeout int `yaml:"timeout"`
}
```

### Step 7: Deprecate Local Implementation

Mark `pkg/authzen/client.go` as deprecated:

```go
// Deprecated: Use github.com/SUNET/go-trust/pkg/authzenclient instead.
// This package will be removed in a future version.
package authzen
```

### Step 8: Tests

Create comprehensive tests per ADR-02 (>70% coverage):

```go
// pkg/keyresolver/gotrust_adapter_test.go
func TestGoTrustResolver_ResolveEd25519(t *testing.T) {
    // Mock server tests
}

func TestGoTrustResolver_EvaluateTrust(t *testing.T) {
    // Trust evaluation tests
}

func TestGoTrustResolver_Discovery(t *testing.T) {
    // Discovery tests
}
```

## Migration Checklist

- [ ] Add go-trust dependency
- [ ] Create `GoTrustResolver` adapter
- [ ] Add ECDSA support to Resolver interface
- [ ] Add DID document parsing helpers
- [ ] Update EdDSA suite to use resolver
- [ ] Update ECDSA suite to use resolver
- [ ] Add configuration for trust registry
- [ ] Write unit tests (>70% coverage)
- [ ] Deprecate local authzen package
- [ ] Update documentation
- [ ] Test with real trust registry

## Timeline Estimate

| Task | Duration |
|------|----------|
| Add dependency & adapter | 1 day |
| ECDSA support | 1 day |
| DID helpers | 1 day |
| Suite updates | 1 day |
| Configuration | 0.5 day |
| Tests | 2 days |
| Documentation | 0.5 day |

**Total: ~7 days**

## Success Criteria

1. All existing tests pass
2. Go-trust resolver can resolve did:key DIDs
3. Go-trust resolver can resolve did:web DIDs via discovery
4. Trust evaluation works with role constraints
5. Test coverage >70%
6. Local authzen package deprecated with clear migration path

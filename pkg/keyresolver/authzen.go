//go:build vc20

package keyresolver

import (
	"crypto/ed25519"
	"fmt"

	"vc/pkg/authzen"
)

// TrustEvaluator validates whether a resolved key should be trusted
// This is separate from key resolution - it evaluates trust in name-to-key bindings
type TrustEvaluator interface {
	// EvaluateTrust checks if the given public key is authorized for the subject ID
	// Returns true if trusted, false otherwise
	EvaluateTrust(subjectID string, publicKey ed25519.PublicKey, role string) (bool, error)
}

// AuthZENTrustEvaluator uses the AuthZEN Trust protocol for trust evaluation
type AuthZENTrustEvaluator struct {
	client *authzen.Client
}

// NewAuthZENTrustEvaluator creates a trust evaluator using AuthZEN protocol
func NewAuthZENTrustEvaluator(baseURL string) *AuthZENTrustEvaluator {
	return &AuthZENTrustEvaluator{
		client: authzen.NewClient(baseURL),
	}
}

// EvaluateTrust validates the name-to-key binding via AuthZEN
func (a *AuthZENTrustEvaluator) EvaluateTrust(subjectID string, publicKey ed25519.PublicKey, role string) (bool, error) {
	// Convert Ed25519 public key to JWK format for AuthZEN evaluation
	jwk := authzen.JWKFromEd25519(publicKey)

	decision, err := a.client.EvaluateJWK(subjectID, jwk, role)
	if err != nil {
		return false, fmt.Errorf("authzen trust evaluation failed: %w", err)
	}

	return decision, nil
}

// GetClient returns the underlying AuthZEN client for advanced usage
func (a *AuthZENTrustEvaluator) GetClient() *authzen.Client {
	return a.client
}

// ValidatingResolver wraps a resolver with trust evaluation
// It first resolves the key, then validates it via a trust evaluator
type ValidatingResolver struct {
	resolver  Resolver
	evaluator TrustEvaluator
	role      string // Optional role to require
}

// NewValidatingResolver creates a resolver that validates trust after resolution
func NewValidatingResolver(resolver Resolver, evaluator TrustEvaluator, role string) *ValidatingResolver {
	return &ValidatingResolver{
		resolver:  resolver,
		evaluator: evaluator,
		role:      role,
	}
}

// ResolveEd25519 resolves the key and validates trust
func (v *ValidatingResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	// First, resolve the key
	key, err := v.resolver.ResolveEd25519(verificationMethod)
	if err != nil {
		return nil, err
	}

	// Then, validate trust
	trusted, err := v.evaluator.EvaluateTrust(verificationMethod, key, v.role)
	if err != nil {
		return nil, fmt.Errorf("trust evaluation failed: %w", err)
	}

	if !trusted {
		return nil, fmt.Errorf("key not trusted for %s", verificationMethod)
	}

	return key, nil
}

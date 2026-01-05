// Package trust provides a unified trust evaluation interface for all credential formats.
//
// This package bridges the gap between different credential formats' trust models:
//   - W3C VC 2.0 Data Integrity: uses DIDs for key identification
//   - SD-JWT VC: uses x5c certificate chains with issuer URLs
//   - ISO mDOC: uses IACA certificate chains with document signer certificates
//
// The key distinction is between:
//   - Name-to-key RESOLUTION: Given a name (DID), fetch the associated public key
//   - Name-to-key VALIDATION: Given a name and key, verify the binding is trusted
//
// When DIDs are used, go-trust can perform resolution. When certificates are used
// (SD-JWT x5c, mDOC MSO), the key is already present, so only validation is needed.
//
// This package provides the TrustEvaluator interface that can be implemented by:
//   - go-trust AuthZEN client (for federation/trust framework queries)
//   - Local trust lists (for offline validation against configured anchors)
//   - Composite evaluators (try multiple sources)
package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
)

// TrustDecision represents the result of a trust evaluation.
type TrustDecision struct {
	// Trusted indicates whether the name-to-key binding is authorized.
	Trusted bool

	// Reason provides explanation for the decision.
	Reason string

	// TrustFramework identifies which trust framework was used (e.g., "eudi", "openid_federation").
	TrustFramework string

	// Metadata contains additional trust metadata (e.g., DID document, entity configuration).
	Metadata any
}

// KeyType indicates the format of the public key being validated.
type KeyType string

const (
	// KeyTypeJWK indicates a JWK (JSON Web Key) format key.
	KeyTypeJWK KeyType = "jwk"
	// KeyTypeX5C indicates an X.509 certificate chain.
	KeyTypeX5C KeyType = "x5c"
)

// Role represents the expected role of the key holder.
type Role string

const (
	// RoleIssuer indicates the key should be authorized for credential issuance.
	RoleIssuer Role = "issuer"
	// RoleVerifier indicates the key should be authorized for credential verification.
	RoleVerifier Role = "verifier"
	// RoleWalletProvider indicates the key is for a wallet provider.
	RoleWalletProvider Role = "wallet_provider"
	// RolePIDProvider indicates the key is for a PID (Person Identification Data) provider.
	RolePIDProvider Role = "pid-provider"
	// RoleCredentialIssuer indicates an OpenID4VCI credential issuer.
	RoleCredentialIssuer Role = "credential-issuer"
	// RoleCredentialVerifier indicates an OpenID4VP credential verifier.
	RoleCredentialVerifier Role = "credential-verifier"
	// RoleAny indicates no specific role constraint.
	RoleAny Role = ""
)

// EvaluationRequest contains the parameters for a trust evaluation.
type EvaluationRequest struct {
	// SubjectID is the identifier of the entity (DID, issuer URL, etc.).
	SubjectID string

	// KeyType indicates the format of the key.
	KeyType KeyType

	// Key is the public key to validate. Can be:
	//   - map[string]any for JWK
	//   - []*x509.Certificate for x5c
	//   - crypto.PublicKey for raw keys
	Key any

	// Role is the expected role (optional). This is converted to action.name
	// when using go-trust, enabling policy-based routing.
	Role Role

	// Action is an explicit policy name to use (optional).
	// If set, this takes precedence over Role for determining the action.name.
	// This allows direct mapping to go-trust server-side policies.
	Action string

	// CredentialType is the type of credential (e.g., "PID", "mDL", "VerifiableCredential").
	// This can influence policy selection when combined with Role.
	CredentialType string

	// DocType is the ISO mDOC document type (for mDOC credentials).
	DocType string

	// Options contains additional trust evaluation options.
	Options *TrustOptions
}

// TrustOptions contains additional options for trust evaluation.
// These options are protocol-agnostic and are translated to go-trust
// context parameters server-side.
type TrustOptions struct {
	// IncludeTrustChain requests the full trust chain in the response.
	IncludeTrustChain bool

	// IncludeCertificates requests X.509 certificates in the response.
	IncludeCertificates bool

	// BypassCache requests that cached results be bypassed.
	BypassCache bool
}

// GetEffectiveAction returns the action name to use for policy routing.
// Priority: 1. Explicit Action field, 2. Composed from Role + CredentialType, 3. Role alone
func (r *EvaluationRequest) GetEffectiveAction() string {
	// If explicit action is set, use it
	if r.Action != "" {
		return r.Action
	}

	// If no role, no action
	if r.Role == "" {
		return ""
	}

	// For PID credentials with issuer role, use pid-provider policy
	if r.CredentialType == "PID" && r.Role == RoleIssuer {
		return string(RolePIDProvider)
	}

	// For credential issuers, use credential-issuer policy
	if r.Role == RoleIssuer && r.CredentialType != "" {
		return string(RoleCredentialIssuer)
	}

	// For verifiers, use credential-verifier policy
	if r.Role == RoleVerifier {
		return string(RoleCredentialVerifier)
	}

	// Fall back to role
	return string(r.Role)
}

// TrustEvaluator evaluates whether a name-to-key binding is trusted.
// Implementations can use go-trust (AuthZEN), local trust lists, or both.
type TrustEvaluator interface {
	// Evaluate checks if the given key is trusted for the specified subject and role.
	// This is used when the key is already known (SD-JWT x5c, mDOC certificates).
	Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)

	// SupportsKeyType returns true if this evaluator can handle the given key type.
	SupportsKeyType(kt KeyType) bool
}

// KeyResolver resolves public keys from identifiers.
// This is used when the key needs to be fetched (DID-based credentials).
type KeyResolver interface {
	// ResolveKey retrieves the public key for the given verification method.
	ResolveKey(ctx context.Context, verificationMethod string) (crypto.PublicKey, error)
}

// CombinedTrustService combines evaluation and resolution capabilities.
// This is the full interface for trust management across all credential formats.
type CombinedTrustService interface {
	TrustEvaluator
	KeyResolver
}

// X5CCertChain is a helper type for x5c certificate chains.
type X5CCertChain []*x509.Certificate

// GetLeafCert returns the end-entity certificate (first in chain).
func (c X5CCertChain) GetLeafCert() *x509.Certificate {
	if len(c) == 0 {
		return nil
	}
	return c[0]
}

// GetRootCert returns the root certificate (last in chain).
func (c X5CCertChain) GetRootCert() *x509.Certificate {
	if len(c) == 0 {
		return nil
	}
	return c[len(c)-1]
}

// GetSubjectID extracts a subject identifier from the leaf certificate.
// Returns the Subject CN or the first SAN URI/DNS name.
func (c X5CCertChain) GetSubjectID() string {
	leaf := c.GetLeafCert()
	if leaf == nil {
		return ""
	}

	// Try Subject CN first
	if leaf.Subject.CommonName != "" {
		return leaf.Subject.CommonName
	}

	// Try SAN URIs
	for _, uri := range leaf.URIs {
		return uri.String()
	}

	// Try SAN DNS names
	if len(leaf.DNSNames) > 0 {
		return leaf.DNSNames[0]
	}

	return ""
}

// ToBase64Strings converts the certificate chain to base64-encoded DER strings.
// This is the format expected by JWK x5c arrays.
func (c X5CCertChain) ToBase64Strings() []string {
	result := make([]string, len(c))
	for i, cert := range c {
		result[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	return result
}

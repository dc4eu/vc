//go:build vc20

package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
	
	"vc/pkg/vc20/credential"
	"vc/pkg/vc20/crypto/keys"
)

// VerificationMethodResolver is an interface for resolving verification methods to public keys.
// This allows different implementations for DID resolution, key registries, etc.
type VerificationMethodResolver interface {
	// ResolvePublicKey resolves a verification method identifier to a public key
	ResolvePublicKey(verificationMethod string) (*ecdsa.PublicKey, error)
}

// StaticKeyResolver is a simple resolver that uses a map of verification methods to keys.
// Useful for testing and simple scenarios.
type StaticKeyResolver struct {
	keys map[string]*ecdsa.PublicKey
}

// NewStaticKeyResolver creates a new static key resolver
func NewStaticKeyResolver() *StaticKeyResolver {
	return &StaticKeyResolver{
		keys: make(map[string]*ecdsa.PublicKey),
	}
}

// AddKey adds a key to the resolver
func (r *StaticKeyResolver) AddKey(verificationMethod string, publicKey *ecdsa.PublicKey) {
	r.keys[verificationMethod] = publicKey
}

// ResolvePublicKey resolves a verification method to a public key
func (r *StaticKeyResolver) ResolvePublicKey(verificationMethod string) (*ecdsa.PublicKey, error) {
	key, ok := r.keys[verificationMethod]
	if !ok {
		return nil, fmt.Errorf("verification method not found: %s", verificationMethod)
	}
	return key, nil
}

// MultikeyResolver resolves public keys from embedded multikey values in proofs
type MultikeyResolver struct{}

// NewMultikeyResolver creates a new multikey resolver
func NewMultikeyResolver() *MultikeyResolver {
	return &MultikeyResolver{}
}

// ResolvePublicKey attempts to extract a multikey from the verification method
// This is a placeholder - in practice, this would fetch the key from the verification method
func (r *MultikeyResolver) ResolvePublicKey(verificationMethod string) (*ecdsa.PublicKey, error) {
	return nil, fmt.Errorf("multikey resolver requires DID resolution - not yet implemented")
}

// VerifyCredentialWithProof verifies a credential with its attached proof(s).
// Automatically detects whether the proof is a base proof or derived proof.
func (s *Suite) VerifyCredentialWithProof(cred *credential.VerifiableCredential, resolver VerificationMethodResolver) (bool, error) {
	if cred == nil {
		return false, fmt.Errorf("credential cannot be nil")
	}
	if cred.Proof == nil {
		return false, fmt.Errorf("credential has no proof")
	}

	// Handle single proof or array of proofs
	switch p := cred.Proof.(type) {
	case *credential.DataIntegrityProof:
		return s.VerifyProof(cred, p, resolver)
	case []*credential.DataIntegrityProof:
		// Verify all proofs - all must pass
		for i, proof := range p {
			valid, err := s.VerifyProof(cred, proof, resolver)
			if err != nil {
				return false, fmt.Errorf("failed to verify proof %d: %w", i, err)
			}
			if !valid {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported proof type: %T", cred.Proof)
	}
}

// VerifyProof verifies a single proof on a credential.
// Automatically detects whether it's a base proof or derived proof by examining the proof value.
func (s *Suite) VerifyProof(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof, resolver VerificationMethodResolver) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("proof cannot be nil")
	}
	if proof.Cryptosuite != "ecdsa-sd-2023" {
		return false, fmt.Errorf("unsupported cryptosuite: %s", proof.Cryptosuite)
	}

	// Detect proof type by attempting to decode
	// Base proofs and derived proofs have different CBOR structures
	if isBaseProof(proof.ProofValue) {
		return s.VerifyBaseProofWithResolver(cred, proof, resolver)
	} else {
		return s.VerifyDerivedProofWithResolver(cred, proof, resolver)
	}
}

// isBaseProof checks if a proof value appears to be a base proof
// Base proofs have tag 0xd95d00, derived proofs have tag 0xd95d01
func isBaseProof(proofValue string) bool {
	// Decode multibase to check CBOR tag
	_, decoded, err := multibase.Decode(proofValue)
	if err != nil || len(decoded) < 3 {
		return false
	}
	// Check for base proof tag: 0xd9 0x5d 0x00
	return decoded[0] == 0xd9 && decoded[1] == 0x5d && decoded[2] == 0x00
}

// VerifyBaseProofWithResolver verifies a base proof using a verification method resolver
func (s *Suite) VerifyBaseProofWithResolver(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof, resolver VerificationMethodResolver) (bool, error) {
	// Decode base proof to extract public key
	baseComponents, err := DecodeBaseProof(proof.ProofValue)
	if err != nil {
		return false, fmt.Errorf("failed to decode base proof: %w", err)
	}

	// Extract public key from proof components
	publicKey, err := s.extractPublicKeyFromBaseProof(baseComponents)
	if err != nil {
		return false, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Use the existing VerifyBaseProof logic
	return s.verifyBaseProofInternal(cred, proof, publicKey, baseComponents)
}

// extractPublicKeyFromBaseProof extracts the public key from base proof components
func (s *Suite) extractPublicKeyFromBaseProof(components *BaseProofComponents) (*ecdsa.PublicKey, error) {
	if len(components.PublicKey) == 0 {
		return nil, fmt.Errorf("public key is empty")
	}

	// The public key is stored in compressed form
	// For P-256, it's 33 bytes; for P-384, it's 49 bytes
	keyLen := len(components.PublicKey)
	
	var curve elliptic.Curve
	if keyLen == 33 {
		curve = elliptic.P256()
	} else if keyLen == 49 {
		curve = elliptic.P384()
	} else {
		return nil, fmt.Errorf("invalid public key length: %d", keyLen)
	}

	// Decompress the public key
	x, y := elliptic.UnmarshalCompressed(curve, components.PublicKey)
	if x == nil {
		return nil, fmt.Errorf("failed to decompress public key")
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// verifyBaseProofInternal is the internal base proof verification logic
func (s *Suite) verifyBaseProofInternal(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof, publicKey *ecdsa.PublicKey, baseComponents *BaseProofComponents) (bool, error) {
	// Create a copy of the credential without proof
	credCopy := *cred
	credCopy.Proof = nil

	// Canonicalize the credential
	credJSON, err := json.Marshal(credCopy)
	if err != nil {
		return false, fmt.Errorf("failed to marshal credential: %w", err)
	}

	nquads, err := s.Canonicalizer.Canonicalize(credJSON)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize credential: %w", err)
	}

	// Extract and randomize blank nodes
	blankNodeLabels := ExtractBlankNodeLabels(nquads)
	transformedNQuads := nquads
	if len(blankNodeLabels) > 0 {
		hmacKey := HMACKey(baseComponents.HMACKey)
		labelMap, err := hmacKey.RandomizeBlankNodeLabels(blankNodeLabels)
		if err != nil {
			return false, fmt.Errorf("failed to randomize blank nodes: %w", err)
		}
		transformedNQuads = replaceBlankNodeLabelsInternal(nquads, labelMap)
	}

	// Recreate proof configuration
	proofOptions := map[string]interface{}{
		"verificationMethod": proof.VerificationMethod,
		"proofPurpose":       proof.ProofPurpose,
		"created":            proof.Created,
	}
	proofConfigMap, err := s.CreateProofConfig(proofOptions)
	if err != nil {
		return false, fmt.Errorf("failed to create proof configuration: %w", err)
	}

	// Canonicalize proof configuration
	proofConfigJSON, err := json.Marshal(proofConfigMap)
	if err != nil {
		return false, fmt.Errorf("failed to marshal proof configuration: %w", err)
	}

	proofConfigNQuads, err := s.Canonicalizer.Canonicalize(proofConfigJSON)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize proof configuration: %w", err)
	}

	// Combine and hash
	combinedNQuads := transformedNQuads + proofConfigNQuads
	hash := sha256.Sum256([]byte(combinedNQuads))

	// Verify signature
	return s.VerifySignature(publicKey, hash[:], baseComponents.Signature)
}

// VerifyDerivedProofWithResolver verifies a derived proof using a verification method resolver
func (s *Suite) VerifyDerivedProofWithResolver(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof, resolver VerificationMethodResolver) (bool, error) {
	if cred == nil {
		return false, fmt.Errorf("credential cannot be nil")
	}
	if proof == nil {
		return false, fmt.Errorf("proof cannot be nil")
	}

	// Decode derived proof
	derivedComponents, err := DecodeDerivedProof(proof.ProofValue)
	if err != nil {
		return false, fmt.Errorf("failed to decode derived proof: %w", err)
	}

	// Resolve public key from verification method
	var publicKey *ecdsa.PublicKey
	if resolver != nil {
		publicKey, err = resolver.ResolvePublicKey(proof.VerificationMethod)
		if err != nil {
			return false, fmt.Errorf("failed to resolve verification method: %w", err)
		}
	} else {
		return false, fmt.Errorf("verification method resolver is required for derived proofs")
	}

	// Verify the derived proof
	return s.verifyDerivedProofInternal(cred, proof, publicKey, derivedComponents)
}

// verifyDerivedProofInternal is the internal derived proof verification logic
func (s *Suite) verifyDerivedProofInternal(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof, publicKey *ecdsa.PublicKey, derivedComponents *DerivedProofComponents) (bool, error) {
	// Create a copy of the credential without proof
	credCopy := *cred
	credCopy.Proof = nil

	// Canonicalize the disclosed credential
	credJSON, err := json.Marshal(credCopy)
	if err != nil {
		return false, fmt.Errorf("failed to marshal credential: %w", err)
	}

	nquads, err := s.Canonicalizer.Canonicalize(credJSON)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize credential: %w", err)
	}

	// For derived proofs, we need to verify that:
	// 1. The signature matches the disclosed data
	// 2. The mandatory indexes are present
	// 3. The selective indexes are consistent with the disclosed data

	// Recreate proof configuration
	proofOptions := map[string]interface{}{
		"verificationMethod": proof.VerificationMethod,
		"proofPurpose":       proof.ProofPurpose,
		"created":            proof.Created,
	}
	proofConfigMap, err := s.CreateProofConfig(proofOptions)
	if err != nil {
		return false, fmt.Errorf("failed to create proof configuration: %w", err)
	}

	// Canonicalize proof configuration
	proofConfigJSON, err := json.Marshal(proofConfigMap)
	if err != nil {
		return false, fmt.Errorf("failed to marshal proof configuration: %w", err)
	}

	proofConfigNQuads, err := s.Canonicalizer.Canonicalize(proofConfigJSON)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize proof configuration: %w", err)
	}

	// Combine and hash
	combinedNQuads := nquads + proofConfigNQuads
	hash := sha256.Sum256([]byte(combinedNQuads))

	// Compare with presentation header
	if len(derivedComponents.PresentationHeader) > 0 {
		// Verify that the presentation header matches the hash
		if len(derivedComponents.PresentationHeader) != len(hash) {
			return false, fmt.Errorf("presentation header length mismatch")
		}
		for i := range hash {
			if hash[i] != derivedComponents.PresentationHeader[i] {
				return false, nil // Presentation header doesn't match
			}
		}
	}

	// Verify signature
	// Note: For derived proofs, the signature from the base proof is reused
	// We verify it against the presentation header
	return s.VerifySignature(publicKey, derivedComponents.PresentationHeader, derivedComponents.Signature)
}

// replaceBlankNodeLabelsInternal replaces blank node labels (internal helper)
func replaceBlankNodeLabelsInternal(nquads string, labelMap CanonicalIdMap) string {
	result := nquads
	for canonical, randomized := range labelMap {
		result = strings.ReplaceAll(result, string(canonical), randomized)
	}
	return result
}

// ExtractPublicKeyFromMultikey extracts a public key from a Multikey string
func (s *Suite) ExtractPublicKeyFromMultikey(multikey string) (*ecdsa.PublicKey, error) {
	return keys.MultikeyToECDSAPublicKey(multikey)
}

// ValidateProofChain validates a chain of proofs on a credential
// This is useful for credentials with multiple proofs (e.g., issuer + holder)
func (s *Suite) ValidateProofChain(cred *credential.VerifiableCredential, resolvers []VerificationMethodResolver) (bool, error) {
	if cred == nil {
		return false, fmt.Errorf("credential cannot be nil")
	}
	if cred.Proof == nil {
		return false, fmt.Errorf("credential has no proof")
	}

	switch p := cred.Proof.(type) {
	case []*credential.DataIntegrityProof:
		if len(p) != len(resolvers) {
			return false, fmt.Errorf("number of proofs (%d) does not match number of resolvers (%d)", len(p), len(resolvers))
		}
		for i, proof := range p {
			valid, err := s.VerifyProof(cred, proof, resolvers[i])
			if err != nil {
				return false, fmt.Errorf("proof %d verification failed: %w", i, err)
			}
			if !valid {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("proof chain validation requires array of proofs")
	}
}

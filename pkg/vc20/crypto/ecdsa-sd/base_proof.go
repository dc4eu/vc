//go:build vc20

package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"vc/pkg/vc20/credential"
)

// BaseProofOptions contains options for creating a base proof
type BaseProofOptions struct {
	// VerificationMethod is the identifier for the public key
	VerificationMethod string

	// ProofPurpose describes the purpose of the proof (e.g., "assertionMethod")
	ProofPurpose string

	// Created is the timestamp when the proof was created (optional, defaults to now)
	Created *time.Time

	// MandatoryPointers are JSON Pointers that MUST always be disclosed
	MandatoryPointers []string

	// Challenge for domain binding (optional)
	Challenge string

	// Domain for domain binding (optional)
	Domain string
}

// CreateBaseProof creates a base proof for a credential using ECDSA-SD-2023
// This is the issuer-side operation that creates a selectively disclosable proof
func (s *Suite) CreateBaseProof(cred *credential.VerifiableCredential, privateKey *ecdsa.PrivateKey, options BaseProofOptions) (*credential.DataIntegrityProof, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential cannot be nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key cannot be nil")
	}
	if options.VerificationMethod == "" {
		return nil, fmt.Errorf("verification method is required")
	}
	if options.ProofPurpose == "" {
		return nil, fmt.Errorf("proof purpose is required")
	}

	// Validate that the private key matches the suite's curve
	if privateKey.Curve != s.Curve {
		return nil, fmt.Errorf("private key curve %s does not match suite curve %s",
			privateKey.Curve.Params().Name, s.Curve.Params().Name)
	}

	// Set creation timestamp if not provided
	created := time.Now().UTC()
	if options.Created != nil {
		created = *options.Created
	}

	// Step 1: Create a copy of the credential without any existing proof
	credCopy := *cred
	credCopy.Proof = nil

	// Step 2: Canonicalize the credential to N-Quads
	credJSON, err := json.Marshal(credCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	nquads, err := s.Canonicalizer.Canonicalize(credJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize credential: %w", err)
	}

	// Step 3: Extract blank node labels from canonical form
	blankNodeLabels := ExtractBlankNodeLabels(nquads)

	// Step 4: Generate HMAC key for blank node randomization
	hmacKey, err := GenerateHMACKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
	}

	// Step 5: Randomize blank node labels if present
	transformedNQuads := nquads
	if len(blankNodeLabels) > 0 {
		labelMap, err := hmacKey.RandomizeBlankNodeLabels(blankNodeLabels)
		if err != nil {
			return nil, fmt.Errorf("failed to randomize blank nodes: %w", err)
		}
		// Replace canonical labels with randomized labels in the N-Quads
		transformedNQuads = replaceBlankNodeLabels(nquads, labelMap)
	}

	// Step 6: Create proof configuration
	proofOptions := map[string]interface{}{
		"verificationMethod": options.VerificationMethod,
		"proofPurpose":       options.ProofPurpose,
		"created":            created.Format(time.RFC3339),
	}
	proofConfig, err := s.CreateProofConfig(proofOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof configuration: %w", err)
	}
	
	// Add optional fields to proof configuration
	if options.Challenge != "" {
		proofConfig["challenge"] = options.Challenge
	}
	if options.Domain != "" {
		proofConfig["domain"] = options.Domain
	}

	// Step 7: Canonicalize proof configuration
	proofConfigJSON, err := json.Marshal(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof configuration: %w", err)
	}

	proofConfigNQuads, err := s.Canonicalizer.Canonicalize(proofConfigJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize proof configuration: %w", err)
	}

	// Step 8: Combine and hash the transformed data (credential + proof config)
	combinedNQuads := transformedNQuads + proofConfigNQuads
	hash := sha256.Sum256([]byte(combinedNQuads))
	hashData := hash[:]

	// Step 9: Sign the hash with ECDSA
	signature, err := s.SignData(privateKey, hashData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// Step 10: Convert public key to compressed bytes
	publicKeyBytes := elliptic.MarshalCompressed(s.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// Step 11: Encode the base proof components to CBOR
	baseProofComponents := &BaseProofComponents{
		Signature:         signature,
		HMACKey:           hmacKey,
		PublicKey:         publicKeyBytes,
		MandatoryPointers: options.MandatoryPointers,
	}

	proofValue, err := EncodeBaseProof(baseProofComponents)
	if err != nil {
		return nil, fmt.Errorf("failed to encode base proof: %w", err)
	}

	// Step 12: Create the proof object
	proof := &credential.DataIntegrityProof{
		Type:               credential.ProofTypeDataIntegrity,
		Cryptosuite:        CryptosuiteID,
		Created:            created.Format(time.RFC3339),
		VerificationMethod: options.VerificationMethod,
		ProofPurpose:       options.ProofPurpose,
		ProofValue:         proofValue,
	}

	// Add optional fields
	if options.Challenge != "" {
		// Note: Challenge would need to be added to DataIntegrityProof struct
		// For now, we'll include it in the proof configuration which is part of the signature
	}
	if options.Domain != "" {
		// Note: Domain would need to be added to DataIntegrityProof struct
		// For now, we'll include it in the proof configuration which is part of the signature
	}

	return proof, nil
}

// AddBaseProof creates a base proof and adds it to the credential
// This is a convenience function that calls CreateBaseProof and attaches the proof
func (s *Suite) AddBaseProof(cred *credential.VerifiableCredential, privateKey *ecdsa.PrivateKey, options BaseProofOptions) error {
	proof, err := s.CreateBaseProof(cred, privateKey, options)
	if err != nil {
		return err
	}

	// Handle both single proof and proof array cases
	if cred.Proof == nil {
		cred.Proof = proof
	} else {
		// Convert to array if needed
		switch existing := cred.Proof.(type) {
		case []interface{}:
			cred.Proof = append(existing, proof)
		case *credential.DataIntegrityProof:
			cred.Proof = []interface{}{existing, proof}
		default:
			cred.Proof = []interface{}{existing, proof}
		}
	}

	return nil
}

// VerifyBaseProof verifies a base proof on a credential
// This is a basic verification that checks the signature is valid
func (s *Suite) VerifyBaseProof(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof) (bool, error) {
	if cred == nil {
		return false, fmt.Errorf("credential cannot be nil")
	}
	if proof == nil {
		return false, fmt.Errorf("proof cannot be nil")
	}

	// Verify cryptosuite matches
	if proof.Cryptosuite != CryptosuiteID {
		return false, fmt.Errorf("proof cryptosuite %s does not match expected %s", proof.Cryptosuite, CryptosuiteID)
	}

	// Decode the base proof
	baseProofComponents, err := DecodeBaseProof(proof.ProofValue)
	if err != nil {
		return false, fmt.Errorf("failed to decode base proof: %w", err)
	}

	// Decompress the public key
	x, y := elliptic.UnmarshalCompressed(s.Curve, baseProofComponents.PublicKey)
	if x == nil {
		return false, fmt.Errorf("failed to unmarshal compressed public key")
	}
	publicKey := &ecdsa.PublicKey{
		Curve: s.Curve,
		X:     x,
		Y:     y,
	}

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

	// Extract and randomize blank nodes using the HMAC key from the proof
	blankNodeLabels := ExtractBlankNodeLabels(nquads)
	transformedNQuads := nquads
	if len(blankNodeLabels) > 0 {
		hmacKey := HMACKey(baseProofComponents.HMACKey)
		labelMap, err := hmacKey.RandomizeBlankNodeLabels(blankNodeLabels)
		if err != nil {
			return false, fmt.Errorf("failed to randomize blank nodes: %w", err)
		}
		transformedNQuads = replaceBlankNodeLabels(nquads, labelMap)
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

	// Combine and hash the transformed data
	combinedNQuads := transformedNQuads + proofConfigNQuads
	hash := sha256.Sum256([]byte(combinedNQuads))
	hashData := hash[:]

	// Verify the signature
	valid, err := s.VerifySignature(publicKey, hashData, baseProofComponents.Signature)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	return valid, nil
}

// replaceBlankNodeLabels replaces canonical blank node labels with randomized labels in N-Quads
func replaceBlankNodeLabels(nquads string, labelMap CanonicalIdMap) string {
	result := nquads
	for canonical, randomized := range labelMap {
		result = strings.ReplaceAll(result, string(canonical), randomized)
	}
	return result
}

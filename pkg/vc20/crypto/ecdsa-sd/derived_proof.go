//go:build vc20

package ecdsasd

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"vc/pkg/vc20/credential"
)

// DerivedProofOptions contains options for creating a derived proof
type DerivedProofOptions struct {
	// VerificationMethod is the identifier for the public key (from base proof)
	VerificationMethod string

	// ProofPurpose describes the purpose of the proof
	ProofPurpose string

	// Created is the timestamp when the derived proof was created (optional, defaults to now)
	Created *time.Time

	// SelectivePointers are JSON Pointers to fields that should be disclosed
	// If empty, all non-mandatory fields are disclosed
	SelectivePointers []string

	// Challenge for domain binding (optional)
	Challenge string

	// Domain for domain binding (optional)
	Domain string
}

// CreateDerivedProof creates a derived proof from a credential with a base proof.
// This is the holder-side operation that selectively discloses fields.
func (s *Suite) CreateDerivedProof(cred *credential.VerifiableCredential, baseProof *credential.DataIntegrityProof, options DerivedProofOptions) (*credential.VerifiableCredential, *credential.DataIntegrityProof, error) {
	if cred == nil {
		return nil, nil, fmt.Errorf("credential cannot be nil")
	}
	if baseProof == nil {
		return nil, nil, fmt.Errorf("base proof cannot be nil")
	}
	if baseProof.Type != "DataIntegrityProof" {
		return nil, nil, fmt.Errorf("invalid proof type: expected DataIntegrityProof, got %s", baseProof.Type)
	}
	if baseProof.Cryptosuite != "ecdsa-sd-2023" {
		return nil, nil, fmt.Errorf("invalid cryptosuite: expected ecdsa-sd-2023, got %s", baseProof.Cryptosuite)
	}
	if baseProof.ProofValue == "" {
		return nil, nil, fmt.Errorf("base proof value is empty")
	}

	// Decode base proof to get components
	baseComponents, err := DecodeBaseProof(baseProof.ProofValue)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode base proof: %w", err)
	}

	// Determine which fields to disclose
	var disclosurePointers []string
	if len(options.SelectivePointers) > 0 {
		disclosurePointers = options.SelectivePointers
	} else {
		// If no selective pointers specified, disclose everything except mandatory
		// (in practice, this would need to traverse the credential to get all pointers)
		disclosurePointers = []string{}
	}

	// Ensure mandatory pointers are included in disclosure
	allPointers := append([]string{}, baseComponents.MandatoryPointers...)
	for _, ptr := range disclosurePointers {
		if !contains(allPointers, ptr) {
			allPointers = append(allPointers, ptr)
		}
	}

	// Sort pointers for consistent ordering
	sort.Strings(allPointers)

	// Create a copy of the credential with only disclosed fields
	disclosedCred, err := s.selectFields(cred, allPointers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to select fields: %w", err)
	}

	// Canonicalize the disclosed credential
	canonicalCred, err := s.Canonicalizer.Canonicalize(disclosedCred)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to canonicalize disclosed credential: %w", err)
	}

	// Extract blank nodes
	blankNodes := extractBlankNodes(canonicalCred)

	// Re-randomize blank node labels using the HMAC key from base proof
	hmacKey, err := NewHMACKey(baseComponents.HMACKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HMAC key: %w", err)
	}

	labelMap, err := hmacKey.RandomizeBlankNodeLabels(blankNodes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to randomize blank nodes: %w", err)
	}

	// Apply the label substitutions to get randomized N-Quads
	randomizedNQuads := canonicalCred
	for canonical, randomized := range labelMap {
		randomizedNQuads = strings.ReplaceAll(randomizedNQuads, string(canonical), randomized)
	}

	// Create compressed label map (disclosed/undisclosed for each blank node)
	compressedLabelMap := s.createCompressedLabelMap(blankNodes, labelMap)

	// Canonicalize the full credential to get statement indexes
	fullCanonical, err := s.Canonicalizer.Canonicalize(cred)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to canonicalize full credential: %w", err)
	}

	// Calculate mandatory and selective indexes
	mandatoryIndexes, selectiveIndexes := s.calculateIndexes(fullCanonical, randomizedNQuads, baseComponents.MandatoryPointers, allPointers)

	// Create proof configuration for derived proof
	proofConfig := map[string]interface{}{
		"type":               "DataIntegrityProof",
		"cryptosuite":        "ecdsa-sd-2023",
		"verificationMethod": options.VerificationMethod,
		"proofPurpose":       options.ProofPurpose,
	}

	// Set created timestamp
	created := options.Created
	if created == nil {
		now := time.Now()
		created = &now
	}
	proofConfig["created"] = created.Format(time.RFC3339)

	// Add challenge and domain if provided
	if options.Challenge != "" {
		proofConfig["challenge"] = options.Challenge
	}
	if options.Domain != "" {
		proofConfig["domain"] = options.Domain
	}

	// Canonicalize proof configuration
	proofConfigJSON, err := json.Marshal(proofConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal proof config: %w", err)
	}

	var proofConfigData interface{}
	if err := json.Unmarshal(proofConfigJSON, &proofConfigData); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal proof config: %w", err)
	}

	canonicalProofConfig, err := s.Canonicalizer.Canonicalize(proofConfigData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to canonicalize proof config: %w", err)
	}

	// Combine randomized credential and proof config
	combinedNQuads := randomizedNQuads + canonicalProofConfig

	// Hash the combined data
	hash := sha256.Sum256([]byte(combinedNQuads))

	// Create derived proof components
	derivedComponents := &DerivedProofComponents{
		Signature:          baseComponents.Signature, // Reuse base signature
		CompressedLabelMap: compressedLabelMap,
		MandatoryIndexes:   mandatoryIndexes,
		SelectiveIndexes:   selectiveIndexes,
		PresentationHeader: hash[:], // Use hash as presentation header
	}

	// Encode derived proof
	proofValue, err := EncodeDerivedProof(derivedComponents)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode derived proof: %w", err)
	}

	// Create the derived proof
	derivedProof := &credential.DataIntegrityProof{
		Type:               "DataIntegrityProof",
		Cryptosuite:        "ecdsa-sd-2023",
		VerificationMethod: options.VerificationMethod,
		ProofPurpose:       options.ProofPurpose,
		Created:            created.Format(time.RFC3339),
		ProofValue:         proofValue,
	}

	// Note: Challenge and Domain are not part of the standard DataIntegrityProof struct
	// They would need to be added to the struct definition or handled separately

	return disclosedCred, derivedProof, nil
}

// selectFields creates a copy of the credential with only the specified fields
func (s *Suite) selectFields(cred *credential.VerifiableCredential, pointers []string) (*credential.VerifiableCredential, error) {
	if len(pointers) == 0 {
		// If no pointers, return full credential
		return cred, nil
	}

	// Convert credential to map[string]interface{} for SelectFields
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	var credMap map[string]interface{}
	if err := json.Unmarshal(credJSON, &credMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential to map: %w", err)
	}

	// Convert string pointers to JSONPointer type
	jsonPointers := make([]JSONPointer, len(pointers))
	for i, ptr := range pointers {
		jsonPointers[i] = JSONPointer(ptr)
	}

	result, err := SelectFields(credMap, jsonPointers)
	if err != nil {
		return nil, err
	}

	// Convert result back to VerifiableCredential
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal selected fields: %w", err)
	}

	var selectedCred credential.VerifiableCredential
	if err := json.Unmarshal(resultJSON, &selectedCred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal selected credential: %w", err)
	}

	return &selectedCred, nil
}

// createCompressedLabelMap creates a compressed representation of blank node label mappings
func (s *Suite) createCompressedLabelMap(originalLabels []string, labelMap CanonicalIdMap) []byte {
	// For simplicity, encode as JSON array of [original, randomized] pairs
	// In a production implementation, this would use a more compact binary format
	type labelPair struct {
		Original   string `json:"o"`
		Randomized string `json:"r"`
	}

	pairs := make([]labelPair, 0, len(labelMap))
	for _, orig := range originalLabels {
		if rand, ok := labelMap[LabelMapKey(orig)]; ok {
			pairs = append(pairs, labelPair{Original: orig, Randomized: rand})
		}
	}

	// Sort for deterministic output
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Original < pairs[j].Original
	})

	data, _ := json.Marshal(pairs)
	return data
}

// calculateIndexes calculates the mandatory and selective indexes
func (s *Suite) calculateIndexes(fullCanonical, disclosedCanonical string, mandatoryPointers, allPointers []string) ([]int, []int) {
	// Split into statements (N-Quads lines)
	fullStatements := strings.Split(strings.TrimSpace(fullCanonical), "\n")
	disclosedStatements := strings.Split(strings.TrimSpace(disclosedCanonical), "\n")

	// Create a map of disclosed statements for quick lookup
	disclosedMap := make(map[string]bool)
	for _, stmt := range disclosedStatements {
		if stmt != "" {
			disclosedMap[stmt] = true
		}
	}

	var mandatoryIndexes []int
	var selectiveIndexes []int

	// Determine which statements correspond to mandatory vs selective disclosure
	for i, stmt := range fullStatements {
		if stmt == "" {
			continue
		}

		if disclosedMap[stmt] {
			// This statement is disclosed
			// Check if it's from a mandatory pointer
			isMandatory := false
			for _, ptr := range mandatoryPointers {
				if strings.Contains(stmt, ptr) {
					isMandatory = true
					break
				}
			}

			if isMandatory {
				mandatoryIndexes = append(mandatoryIndexes, i)
			} else {
				selectiveIndexes = append(selectiveIndexes, i)
			}
		}
	}

	return mandatoryIndexes, selectiveIndexes
}

// extractBlankNodes extracts all blank node labels from canonicalized N-Quads
func extractBlankNodes(nquads string) []string {
	lines := strings.Split(nquads, "\n")
	nodeSet := make(map[string]bool)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Find blank nodes (start with "_:")
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.HasPrefix(part, "_:") {
				// Extract label (remove trailing punctuation)
				label := strings.TrimRight(part, " .")
				nodeSet[label] = true
			}
		}
	}

	// Convert to sorted slice
	nodes := make([]string, 0, len(nodeSet))
	for node := range nodeSet {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	return nodes
}

// VerifyDerivedProof verifies a derived proof on a credential
// This is a convenience wrapper that requires the public key to be extracted separately.
// For automatic key resolution, use VerifyDerivedProofWithResolver from verify.go
func (s *Suite) VerifyDerivedProof(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof) (bool, error) {
	if cred == nil {
		return false, fmt.Errorf("credential cannot be nil")
	}
	if proof == nil {
		return false, fmt.Errorf("proof cannot be nil")
	}
	if proof.Type != "DataIntegrityProof" {
		return false, fmt.Errorf("invalid proof type: expected DataIntegrityProof, got %s", proof.Type)
	}
	if proof.Cryptosuite != "ecdsa-sd-2023" {
		return false, fmt.Errorf("invalid cryptosuite: expected ecdsa-sd-2023, got %s", proof.Cryptosuite)
	}
	if proof.ProofValue == "" {
		return false, fmt.Errorf("proof value is empty")
	}

	// For derived proof verification, you need to provide a resolver
	// This function is kept for API consistency but requires the full verification flow
	return false, fmt.Errorf("derived proof verification requires a VerificationMethodResolver - use VerifyDerivedProofWithResolver instead")
}

// AddDerivedProof adds a derived proof to a credential, handling multiple proofs
func (s *Suite) AddDerivedProof(cred *credential.VerifiableCredential, proof *credential.DataIntegrityProof) error {
	if cred == nil {
		return fmt.Errorf("credential cannot be nil")
	}
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}

	// Check if Proof field is already set
	if cred.Proof != nil {
		// Convert single proof to array if needed
		switch p := cred.Proof.(type) {
		case *credential.DataIntegrityProof:
			// Single proof exists, convert to array
			cred.Proof = []*credential.DataIntegrityProof{p, proof}
		case []*credential.DataIntegrityProof:
			// Array exists, append
			cred.Proof = append(p, proof)
		default:
			return fmt.Errorf("unexpected proof type: %T", cred.Proof)
		}
	} else {
		// No existing proof, set as single proof
		cred.Proof = proof
	}

	return nil
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// VerifyMandatoryPointers verifies that all mandatory pointers are present in the disclosed credential
func (s *Suite) VerifyMandatoryPointers(cred *credential.VerifiableCredential, mandatoryPointers []string) error {
	if cred == nil {
		return fmt.Errorf("credential cannot be nil")
	}

	// Marshal credential to JSON for pointer evaluation
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal credential: %w", err)
	}

	var credData interface{}
	if err := json.Unmarshal(credJSON, &credData); err != nil {
		return fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	// Check each mandatory pointer
	for _, ptr := range mandatoryPointers {
		_, err := ApplyJSONPointer(credData, JSONPointer(ptr))
		if err != nil {
			return fmt.Errorf("mandatory pointer %s not found: %w", ptr, err)
		}
	}

	return nil
}

// CompareCredentials compares two credentials byte-by-byte after canonicalization
func (s *Suite) CompareCredentials(cred1, cred2 *credential.VerifiableCredential) (bool, error) {
	// Convert credentials to JSON for proper canonicalization
	var cred1JSON, cred2JSON map[string]interface{}

	data1, err := json.Marshal(cred1)
	if err != nil {
		return false, fmt.Errorf("failed to marshal first credential: %w", err)
	}
	if err := json.Unmarshal(data1, &cred1JSON); err != nil {
		return false, fmt.Errorf("failed to unmarshal first credential: %w", err)
	}

	data2, err := json.Marshal(cred2)
	if err != nil {
		return false, fmt.Errorf("failed to marshal second credential: %w", err)
	}
	if err := json.Unmarshal(data2, &cred2JSON); err != nil {
		return false, fmt.Errorf("failed to unmarshal second credential: %w", err)
	}

	canonical1, err := s.Canonicalizer.Canonicalize(cred1JSON)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize first credential: %w", err)
	}

	canonical2, err := s.Canonicalizer.Canonicalize(cred2JSON)
	if err != nil {
		return false, fmt.Errorf("failed to canonicalize second credential: %w", err)
	}

	return bytes.Equal([]byte(canonical1), []byte(canonical2)), nil
}

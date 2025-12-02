package eddsa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"vc/pkg/vc20/credential"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

const (
	Cryptosuite2022 = "eddsa-rdfc-2022"
	ProofType       = "DataIntegrityProof"
)

// Suite implements the EdDSA Cryptosuite v1.0 (eddsa-rdfc-2022)
type Suite struct {
}

// NewSuite creates a new EdDSA cryptosuite
func NewSuite() *Suite {
	return &Suite{}
}

// Verify verifies a credential using eddsa-rdfc-2022
func (s *Suite) Verify(cred *credential.RDFCredential, key ed25519.PublicKey) error {
	if cred == nil {
		return fmt.Errorf("credential is nil")
	}
	if key == nil {
		return fmt.Errorf("public key is nil")
	}

	// 1. Extract proof object
	proofCred, err := cred.GetProofObject()
	if err != nil {
		return fmt.Errorf("failed to get proof object: %w", err)
	}

	// Convert proof to JSON to extract values
	proofJSONBytes, err := proofCred.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to convert proof to JSON: %w", err)
	}

	var proofJSON interface{}
	if err := json.Unmarshal(proofJSONBytes, &proofJSON); err != nil {
		return fmt.Errorf("failed to unmarshal proof JSON: %w", err)
	}

	// Compact the proof JSON to ensure we have short keys
	proc := ld.NewJsonLdProcessor()
	compactOpts := ld.NewJsonLdOptions("")
	compactOpts.DocumentLoader = credential.GetGlobalLoader()
	context := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
	}

	compactedProof, err := proc.Compact(proofJSON, context, compactOpts)
	if err != nil {
		return fmt.Errorf("failed to compact proof JSON: %w", err)
	}

	proofMap := compactedProof

	// Find proof node
	proofNode := findProofNode(proofMap)
	if proofNode == nil {
		return fmt.Errorf("proof node not found in proof object")
	}

	// Get proofValue
	proofValue, ok := proofNode["proofValue"].(string)
	if !ok {
		return fmt.Errorf("proofValue not found or not a string")
	}

	// 2. Decode proofValue (multibase)
	_, signature, err := multibase.Decode(proofValue)
	if err != nil {
		return fmt.Errorf("failed to decode proofValue: %w", err)
	}

	// 3. Fix VC graph structure if needed (workaround for json-gold bug)
	if err := cred.NormalizeVerifiableCredentialGraph(); err != nil {
		return fmt.Errorf("failed to normalize VC graph: %w", err)
	}

	// 4. Canonicalize document (without proof)
	// Determine if we are verifying a VP or VC to remove the correct proof
	targetType := "VerifiableCredential"

	// Check original JSON for type
	originalJSON := cred.GetOriginalJSON()
	if originalJSON != "" {
		var credMap map[string]interface{}
		if err := json.Unmarshal([]byte(originalJSON), &credMap); err == nil {
			if hasType(credMap, "VerifiablePresentation") {
				targetType = "VerifiablePresentation"
			}
		}
	}

	credWithoutProof, err := cred.GetCredentialWithoutProofForTypes(targetType)
	if err != nil {
		return fmt.Errorf("failed to get credential without proof: %w", err)
	}

	docCanonical, err := credWithoutProof.GetCanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of document: %w", err)
	}

	// 5. Create proof configuration (remove proofValue)
	delete(proofNode, "proofValue")

	// Ensure context
	if _, ok := proofNode["@context"]; !ok {
		// Try to use context from credential if available
		if ctx, err := cred.GetContext(); err == nil && ctx != nil {
			proofNode["@context"] = ctx
		} else {
			proofNode["@context"] = "https://www.w3.org/ns/credentials/v2"
		}
	}

	proofConfigBytes, err := json.Marshal(proofNode)
	if err != nil {
		return fmt.Errorf("failed to marshal proof config: %w", err)
	}

	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.DocumentLoader = credential.GetGlobalLoader()
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofConfigCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	proofCanonical, err := proofConfigCred.GetCanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	// 6. Hash
	docHash := sha256.Sum256([]byte(docCanonical))
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Standard is proofHash + docHash
	combined := append(proofHash[:], docHash[:]...)

	if !ed25519.Verify(key, combined, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func hasType(m map[string]interface{}, expectedType string) bool {
	t, ok := m["type"]
	if !ok {
		t, ok = m["@type"]
	}
	if !ok {
		return false
	}

	if s, ok := t.(string); ok {
		return s == expectedType
	}
	if list, ok := t.([]interface{}); ok {
		for _, item := range list {
			if s, ok := item.(string); ok && s == expectedType {
				return true
			}
		}
	}
	return false
}

func findProofNode(data interface{}) map[string]interface{} {
	if m, ok := data.(map[string]interface{}); ok {
		if hasType(m, ProofType) || hasType(m, "Proof") {
			return m
		}
		// Check all values
		for _, v := range m {
			if found := findProofNode(v); found != nil {
				return found
			}
		}
	} else if list, ok := data.([]interface{}); ok {
		for _, item := range list {
			if found := findProofNode(item); found != nil {
				return found
			}
		}
	}
	return nil
}

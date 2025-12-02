package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"vc/pkg/vc20/credential"

	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

const (
	Cryptosuite2019 = "ecdsa-rdfc-2019"
	ProofType       = "DataIntegrityProof"
)

// Suite implements the ECDSA Cryptosuite v1.0
type Suite struct {
}

// NewSuite creates a new ECDSA cryptosuite
func NewSuite() *Suite {
	return &Suite{}
}

// SignOptions contains options for signing
type SignOptions struct {
	VerificationMethod string
	ProofPurpose       string
	Created            time.Time
	Domain             string
	Challenge          string
}

// Sign signs a credential using ecdsa-rdfc-2019
func (s *Suite) Sign(cred *credential.RDFCredential, key *ecdsa.PrivateKey, opts *SignOptions) (*credential.RDFCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if opts == nil {
		return nil, fmt.Errorf("sign options are nil")
	}

	// 1. Get canonical document hash (without proof)
	// We use GetCredentialWithoutProof to ensure we don't include any existing proof
	credWithoutProof, err := cred.GetCredentialWithoutProof()
	if err != nil {
		return nil, fmt.Errorf("failed to get credential without proof: %w", err)
	}

	// 2. Create proof configuration
	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	proofConfig := map[string]interface{}{
		"@context":           "https://www.w3.org/ns/credentials/v2",
		"type":               ProofType,
		"cryptosuite":        Cryptosuite2019,
		"verificationMethod": opts.VerificationMethod,
		"proofPurpose":       opts.ProofPurpose,
		"created":            created.Format(time.RFC3339),
	}

	if opts.Domain != "" {
		proofConfig["domain"] = opts.Domain
	}
	if opts.Challenge != "" {
		proofConfig["challenge"] = opts.Challenge
	}

	// 3. Canonicalize and hash proof configuration
	// We need to convert proofConfig to RDF and then canonicalize
	// We can use a temporary RDFCredential for this
	proofConfigBytes, err := json.Marshal(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof config: %w", err)
	}

	// Use standard JSON-LD options
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.DocumentLoader = credential.GetGlobalLoader()
	// ldOpts.Format = "application/n-quads" // Do not set format, we want RDFDataset
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	// 4. Combine hashes
	// The spec says: hash(proofOptionsHash + documentHash)
	// But wait, GetCanonicalHash returns hex string. We need raw bytes?
	// RDFCredential.GetCanonicalHash returns hex string.
	// We should probably get the canonical form string and hash it ourselves to be sure about concatenation.

	// Let's get canonical forms instead
	docCanonical, err := credWithoutProof.GetCanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of document: %w", err)
	}

	proofCanonical, err := proofCred.GetCanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	// Hash the canonical forms
	docHashBytes := sha256.Sum256([]byte(docCanonical))
	proofHashBytes := sha256.Sum256([]byte(proofCanonical))

	// Concatenate: proofHash + docHash
	combined := append(proofHashBytes[:], docHashBytes[:]...)

	// 5. Sign
	// ECDSA signature
	rInt, sInt, err := ecdsa.Sign(rand.Reader, key, combined)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Serialize signature (r || s)
	curveBits := key.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8

	rBytes := rInt.Bytes()
	sBytes := sInt.Bytes()

	// Pad to key size
	signature := make([]byte, 2*keyBytes)
	copy(signature[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(signature[2*keyBytes-len(sBytes):], sBytes)

	// 6. Encode signature (multibase base58-btc)
	// Header for base58-btc is 'z'
	proofValue, err := multibase.Encode(multibase.Base58BTC, signature)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	// 7. Add proof to credential
	// We need to take the original JSON (or convert dataset to JSON), add proof, and re-parse
	// Since RDFCredential is immutable-ish, we create a new one.

	// Get JSON from original credential (or convert if needed)
	var credMap map[string]interface{}
	originalJSON := cred.GetOriginalJSON()
	if originalJSON != "" {
		if err := json.Unmarshal([]byte(originalJSON), &credMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal original credential: %w", err)
		}
	} else {
		// Convert from RDF
		jsonBytes, err := cred.ToJSON()
		if err != nil {
			return nil, fmt.Errorf("failed to convert credential to JSON: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &credMap); err != nil {
			return nil, fmt.Errorf("failed to unmarshal converted credential: %w", err)
		}
	}

	// Add proofValue to proofConfig
	proofConfig["proofValue"] = proofValue

	// Add proof to credential
	// If proof already exists, it should be an array or we replace it?
	// Usually we append if it's an array, or turn it into an array.
	// For simplicity, let's assume single proof or overwrite for now, or append.
	if existingProof, ok := credMap["proof"]; ok {
		if proofs, ok := existingProof.([]interface{}); ok {
			credMap["proof"] = append(proofs, proofConfig)
		} else {
			credMap["proof"] = []interface{}{existingProof, proofConfig}
		}
	} else {
		credMap["proof"] = proofConfig
	}

	// Create new RDFCredential
	newCredBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new credential: %w", err)
	}

	return credential.NewRDFCredentialFromJSON(newCredBytes, ldOpts)
}

// Verify verifies a credential using ecdsa-rdfc-2019
func (s *Suite) Verify(cred *credential.RDFCredential, key *ecdsa.PublicKey) error {
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

	// We need to get the proofValue from the proof object
	proofJSONBytes, err := proofCred.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to convert proof to JSON: %w", err)
	}

	var proofJSON interface{}
	if err := json.Unmarshal(proofJSONBytes, &proofJSON); err != nil {
		return fmt.Errorf("failed to unmarshal proof JSON: %w", err)
	}

	// Compact the proof JSON to ensure we have short keys (e.g. "proofValue" instead of full URI)
	proc := ld.NewJsonLdProcessor()
	compactOpts := ld.NewJsonLdOptions("")
	compactOpts.DocumentLoader = credential.GetGlobalLoader()
	// Use the V2 context for compaction
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

	proofValue, ok := proofNode["proofValue"].(string)
	if !ok {
		return fmt.Errorf("proofValue not found or not a string")
	}

	// 2. Remove proofValue from proof node to create proof configuration
	delete(proofNode, "proofValue")

	// Ensure context is present for correct RDF conversion
	if _, ok := proofNode["@context"]; !ok {
		proofNode["@context"] = "https://www.w3.org/ns/credentials/v2"
	}

	// 3. Canonicalize proof configuration
	proofConfigBytes, err := json.Marshal(proofNode)
	if err != nil {
		return fmt.Errorf("failed to marshal proof config: %w", err)
	}

	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.DocumentLoader = credential.GetGlobalLoader()
	// ldOpts.Format = "application/n-quads" // Do not set format, we want RDFDataset
	ldOpts.Algorithm = ld.AlgorithmURDNA2015

	proofConfigCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return fmt.Errorf("failed to create RDF credential for proof config: %w", err)
	}

	proofCanonical, err := proofConfigCred.GetCanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of proof config: %w", err)
	}

	// 4. Canonicalize document (without proof)
	credWithoutProof, err := cred.GetCredentialWithoutProof()
	if err != nil {
		return fmt.Errorf("failed to get credential without proof: %w", err)
	}

	docCanonical, err := credWithoutProof.GetCanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form of document: %w", err)
	}

	// 5. Hash
	docHashBytes := sha256.Sum256([]byte(docCanonical))
	proofHashBytes := sha256.Sum256([]byte(proofCanonical))

	combined := append(proofHashBytes[:], docHashBytes[:]...)

	// 6. Verify signature
	_, signature, err := multibase.Decode(proofValue)
	if err != nil {
		return fmt.Errorf("failed to decode proofValue: %w", err)
	}

	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keyBytes {
		return fmt.Errorf("invalid signature length: expected %d, got %d", 2*keyBytes, len(signature))
	}

	rInt := new(big.Int).SetBytes(signature[:keyBytes])
	sInt := new(big.Int).SetBytes(signature[keyBytes:])

	if !ecdsa.Verify(key, combined, rInt, sInt) {
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

//go:build vc20

package ecdsasd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"vc/pkg/vc20/crypto/keys"
	"vc/pkg/vc20/rdfcanon"
)

// CryptosuiteID is the identifier for the ECDSA-SD-2023 cryptosuite
const CryptosuiteID = "ecdsa-sd-2023"

// Suite represents the ECDSA-SD-2023 cryptographic suite for Data Integrity proofs
type Suite struct {
	// Curve is the elliptic curve to use (P-256 or P-384)
	Curve elliptic.Curve
	// Canonicalizer is used for RDF canonicalization
	Canonicalizer *rdfcanon.Canonicalizer
}

// NewSuite creates a new ECDSA-SD-2023 cryptosuite
// Default curve is P-256 (secp256r1)
func NewSuite() *Suite {
	return &Suite{
		Curve:         elliptic.P256(),
		Canonicalizer: rdfcanon.NewCanonicalizer(),
	}
}

// NewSuiteP384 creates a new ECDSA-SD-2023 cryptosuite using P-384 curve
func NewSuiteP384() *Suite {
	return &Suite{
		Curve:         elliptic.P384(),
		Canonicalizer: rdfcanon.NewCanonicalizer(),
	}
}

// ID returns the cryptosuite identifier
func (s *Suite) ID() string {
	return CryptosuiteID
}

// GenerateKeyPair generates a new ECDSA key pair for the configured curve
func (s *Suite) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(s.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	return privKey, nil
}

// GetVerificationMethod creates a verification method object for a public key
// Returns a map suitable for inclusion in a proof
func (s *Suite) GetVerificationMethod(pubKey *ecdsa.PublicKey, methodID string) (map[string]interface{}, error) {
	// Encode public key as Multikey
	multikey, err := keys.ECDSAPublicKeyToMultikey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	// Determine verification method type based on curve
	vmType := "Multikey"

	verificationMethod := map[string]interface{}{
		"id":                 methodID,
		"type":               vmType,
		"controller":         extractController(methodID),
		"publicKeyMultibase": multikey,
	}

	return verificationMethod, nil
}

// extractController extracts the controller DID from a verification method ID
// E.g., "did:example:123#key-1" -> "did:example:123"
func extractController(methodID string) string {
	for i := len(methodID) - 1; i >= 0; i-- {
		if methodID[i] == '#' {
			return methodID[:i]
		}
	}
	return methodID
}

// CreateProofConfig creates the proof configuration object
// This is the data that gets signed in the base proof
func (s *Suite) CreateProofConfig(options map[string]interface{}) (map[string]interface{}, error) {
	proofConfig := make(map[string]interface{})

	// Required fields
	proofConfig["type"] = "DataIntegrityProof"
	proofConfig["cryptosuite"] = CryptosuiteID

	// Copy relevant options
	if verificationMethod, ok := options["verificationMethod"]; ok {
		proofConfig["verificationMethod"] = verificationMethod
	}
	if created, ok := options["created"]; ok {
		proofConfig["created"] = created
	}
	if proofPurpose, ok := options["proofPurpose"]; ok {
		proofConfig["proofPurpose"] = proofPurpose
	} else {
		proofConfig["proofPurpose"] = "assertionMethod"
	}

	return proofConfig, nil
}

// SignData signs data using ECDSA with deterministic k (RFC 6979)
// Returns the raw signature bytes (r || s)
func (s *Suite) SignData(privKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if privKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Verify private key curve matches suite curve
	if privKey.Curve.Params().Name != s.Curve.Params().Name {
		return nil, fmt.Errorf("private key curve %s does not match suite curve %s",
			privKey.Curve.Params().Name, s.Curve.Params().Name)
	}

	// Hash the data
	hash := sha256.Sum256(data)

	// Sign with ECDSA (Go's crypto/ecdsa uses RFC 6979 deterministic k by default)
	r, s_val, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	// Encode as raw bytes (r || s)
	// Each component should be the curve's byte length
	curveByteLen := (s.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*curveByteLen)

	rBytes := r.Bytes()
	sBytes := s_val.Bytes()

	// Pad with leading zeros if needed
	copy(signature[curveByteLen-len(rBytes):curveByteLen], rBytes)
	copy(signature[2*curveByteLen-len(sBytes):], sBytes)

	return signature, nil
}

// VerifySignature verifies an ECDSA signature
func (s *Suite) VerifySignature(pubKey *ecdsa.PublicKey, data []byte, signature []byte) (bool, error) {
	if pubKey == nil {
		return false, fmt.Errorf("public key is nil")
	}

	// Verify public key curve matches suite curve
	if pubKey.Curve.Params().Name != s.Curve.Params().Name {
		return false, fmt.Errorf("public key curve %s does not match suite curve %s",
			pubKey.Curve.Params().Name, s.Curve.Params().Name)
	}

	// Expected signature length is 2 * curve byte length
	curveByteLen := (s.Curve.Params().BitSize + 7) / 8
	expectedLen := 2 * curveByteLen

	if len(signature) != expectedLen {
		return false, fmt.Errorf("invalid signature length: got %d, expected %d", len(signature), expectedLen)
	}

	// Extract r and s from signature
	r := new(big.Int).SetBytes(signature[:curveByteLen])
	s_val := new(big.Int).SetBytes(signature[curveByteLen:])

	// Hash the data
	hash := sha256.Sum256(data)

	// Verify signature
	valid := ecdsa.Verify(pubKey, hash[:], r, s_val)
	return valid, nil
}

// SignatureToDER converts a raw ECDSA signature (r || s) to DER format
// This is useful for compatibility with some systems
func (s *Suite) SignatureToDER(signature []byte) ([]byte, error) {
	curveByteLen := (s.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*curveByteLen {
		return nil, fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:curveByteLen])
	s_val := new(big.Int).SetBytes(signature[curveByteLen:])

	// DER encode
	type ECDSASignature struct {
		R, S *big.Int
	}
	derSig, err := asn1.Marshal(ECDSASignature{R: r, S: s_val})
	if err != nil {
		return nil, fmt.Errorf("DER encoding failed: %w", err)
	}

	return derSig, nil
}

// SignatureFromDER converts a DER-encoded ECDSA signature to raw format (r || s)
func (s *Suite) SignatureFromDER(derSig []byte) ([]byte, error) {
	type ECDSASignature struct {
		R, S *big.Int
	}

	var sig ECDSASignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return nil, fmt.Errorf("DER decoding failed: %w", err)
	}

	curveByteLen := (s.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*curveByteLen)

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()

	// Pad with leading zeros if needed
	copy(signature[curveByteLen-len(rBytes):curveByteLen], rBytes)
	copy(signature[2*curveByteLen-len(sBytes):], sBytes)

	return signature, nil
}

// HashCredential hashes a credential document using RDF canonicalization
func (s *Suite) HashCredential(credential interface{}) ([]byte, error) {
	// Canonicalize the credential
	canonicalNQuads, err := s.Canonicalizer.Canonicalize(credential)
	if err != nil {
		return nil, fmt.Errorf("canonicalization failed: %w", err)
	}

	// Hash the canonical form
	hash := sha256.Sum256([]byte(canonicalNQuads))
	return hash[:], nil
}

// GetCurveName returns the name of the curve used by this suite
func (s *Suite) GetCurveName() string {
	return s.Curve.Params().Name
}

// GetSignatureLength returns the expected signature length in bytes
func (s *Suite) GetSignatureLength() int {
	curveByteLen := (s.Curve.Params().BitSize + 7) / 8
	return 2 * curveByteLen
}

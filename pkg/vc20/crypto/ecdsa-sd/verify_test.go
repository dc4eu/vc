//go:build vc20

package ecdsasd

import (
	"testing"

	"vc/pkg/vc20/credential"
)

func TestStaticKeyResolver(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate a key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Add key to resolver
	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Resolve the key
	resolvedKey, err := resolver.ResolvePublicKey(verificationMethod)
	if err != nil {
		t.Fatalf("Failed to resolve key: %v", err)
	}

	if resolvedKey.X.Cmp(privKey.PublicKey.X) != 0 || resolvedKey.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("Resolved key does not match original key")
	}
}

func TestStaticKeyResolver_NotFound(t *testing.T) {
	resolver := NewStaticKeyResolver()

	_, err := resolver.ResolvePublicKey("did:example:notfound#key-1")
	if err == nil {
		t.Error("Expected error for non-existent verification method")
	}
}

func TestVerifyCredentialWithProof_BaseProof(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Add key to resolver
	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	baseProof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Add proof to credential
	cred.Proof = baseProof

	// Verify credential
	valid, err := suite.VerifyCredentialWithProof(cred, resolver)
	if err != nil {
		t.Fatalf("Failed to verify credential: %v", err)
	}

	if !valid {
		t.Error("Expected credential to be valid")
	}
}

func TestVerifyCredentialWithProof_DerivedProof(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Add key to resolver
	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice Smith",
			"age":  30,
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	baseProof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Create derived proof
	derivedOptions := DerivedProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
		SelectivePointers:  []string{"/credentialSubject/name"},
	}

	disclosedCred, derivedProof, err := suite.CreateDerivedProof(cred, baseProof, derivedOptions)
	if err != nil {
		t.Fatalf("Failed to create derived proof: %v", err)
	}

	// Add proof to disclosed credential
	disclosedCred.Proof = derivedProof

	// Verify credential
	valid, err := suite.VerifyCredentialWithProof(disclosedCred, resolver)
	if err != nil {
		t.Fatalf("Failed to verify credential: %v", err)
	}

	if !valid {
		t.Error("Expected credential to be valid")
	}
}

func TestVerifyCredentialWithProof_MultipleProofs(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Add key to resolver
	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create two base proofs
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	proof1, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create first proof: %v", err)
	}

	proof2, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create second proof: %v", err)
	}

	// Add multiple proofs
	cred.Proof = []*credential.DataIntegrityProof{proof1, proof2}

	// Verify credential
	valid, err := suite.VerifyCredentialWithProof(cred, resolver)
	if err != nil {
		t.Fatalf("Failed to verify credential: %v", err)
	}

	if !valid {
		t.Error("Expected credential to be valid")
	}
}

func TestVerifyCredentialWithProof_NilCredential(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	_, err := suite.VerifyCredentialWithProof(nil, resolver)
	if err == nil {
		t.Error("Expected error for nil credential")
	}
}

func TestVerifyCredentialWithProof_NoProof(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
	}

	_, err := suite.VerifyCredentialWithProof(cred, resolver)
	if err == nil {
		t.Error("Expected error for credential with no proof")
	}
}

func TestVerifyProof_BaseProof(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	proof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Remove proof from credential for verification
	credCopy := *cred
	credCopy.Proof = nil

	// Verify proof
	valid, err := suite.VerifyProof(&credCopy, proof, resolver)
	if err != nil {
		t.Fatalf("Failed to verify proof: %v", err)
	}

	if !valid {
		t.Error("Expected proof to be valid")
	}
}

func TestVerifyProof_InvalidCryptosuite(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
	}

	proof := &credential.DataIntegrityProof{
		Type:        "DataIntegrityProof",
		Cryptosuite: "wrong-suite",
		ProofValue:  "test",
	}

	_, err := suite.VerifyProof(cred, proof, resolver)
	if err == nil {
		t.Error("Expected error for invalid cryptosuite")
	}
}

func TestIsBaseProof(t *testing.T) {
	suite := NewSuite()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	baseProof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Check if it's detected as base proof
	if !isBaseProof(baseProof.ProofValue) {
		t.Error("Expected proof to be detected as base proof")
	}

	// Create derived proof
	derivedOptions := DerivedProofOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		SelectivePointers:  []string{"/credentialSubject"},
	}

	_, derivedProof, err := suite.CreateDerivedProof(cred, baseProof, derivedOptions)
	if err != nil {
		t.Fatalf("Failed to create derived proof: %v", err)
	}

	// Check if it's NOT detected as base proof
	if isBaseProof(derivedProof.ProofValue) {
		t.Error("Expected proof to NOT be detected as base proof")
	}
}

func TestExtractPublicKeyFromBaseProof_P256(t *testing.T) {
	suite := NewSuite()

	// Generate P-256 key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create credential and proof
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	baseOptions := BaseProofOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	baseProof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Decode proof
	components, err := DecodeBaseProof(baseProof.ProofValue)
	if err != nil {
		t.Fatalf("Failed to decode base proof: %v", err)
	}

	// Extract public key
	extractedKey, err := suite.extractPublicKeyFromBaseProof(components)
	if err != nil {
		t.Fatalf("Failed to extract public key: %v", err)
	}

	// Verify it matches the original
	if extractedKey.X.Cmp(privKey.PublicKey.X) != 0 || extractedKey.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("Extracted key does not match original key")
	}
}

func TestExtractPublicKeyFromBaseProof_P384(t *testing.T) {
	suite := NewSuiteP384()

	// Generate P-384 key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create credential and proof
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	baseOptions := BaseProofOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
	}

	baseProof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Decode proof
	components, err := DecodeBaseProof(baseProof.ProofValue)
	if err != nil {
		t.Fatalf("Failed to decode base proof: %v", err)
	}

	// Extract public key
	extractedKey, err := suite.extractPublicKeyFromBaseProof(components)
	if err != nil {
		t.Fatalf("Failed to extract public key: %v", err)
	}

	// Verify it matches the original
	if extractedKey.X.Cmp(privKey.PublicKey.X) != 0 || extractedKey.Y.Cmp(privKey.PublicKey.Y) != 0 {
		t.Error("Extracted key does not match original key")
	}
}

func TestVerifyBaseProofWithResolver(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	proof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Verify with resolver
	valid, err := suite.VerifyBaseProofWithResolver(cred, proof, resolver)
	if err != nil {
		t.Fatalf("Failed to verify base proof: %v", err)
	}

	if !valid {
		t.Error("Expected proof to be valid")
	}
}

func TestVerifyDerivedProofWithResolver(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id":   "did:example:subject",
			"name": "Alice",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	baseProof, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	// Create derived proof
	derivedOptions := DerivedProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
		SelectivePointers:  []string{"/credentialSubject/name"},
	}

	disclosedCred, derivedProof, err := suite.CreateDerivedProof(cred, baseProof, derivedOptions)
	if err != nil {
		t.Fatalf("Failed to create derived proof: %v", err)
	}

	// Verify with resolver
	valid, err := suite.VerifyDerivedProofWithResolver(disclosedCred, derivedProof, resolver)
	if err != nil {
		t.Fatalf("Failed to verify derived proof: %v", err)
	}

	if !valid {
		t.Error("Expected proof to be valid")
	}
}

func TestVerifyDerivedProofWithResolver_NoResolver(t *testing.T) {
	suite := NewSuite()

	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
	}

	proof := &credential.DataIntegrityProof{
		Type:        "DataIntegrityProof",
		Cryptosuite: "ecdsa-sd-2023",
		ProofValue:  "test",
	}

	_, err := suite.VerifyDerivedProofWithResolver(cred, proof, nil)
	if err == nil {
		t.Error("Expected error when resolver is nil")
	}
}

func TestValidateProofChain(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate key pair
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	verificationMethod := "did:example:issuer#key-1"
	resolver.AddKey(verificationMethod, &privKey.PublicKey)

	// Create credential
	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Issuer: map[string]interface{}{
			"id": "did:example:issuer",
		},
		CredentialSubject: map[string]interface{}{
			"id": "did:example:subject",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Create two proofs
	baseOptions := BaseProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       "assertionMethod",
	}

	proof1, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create first proof: %v", err)
	}

	proof2, err := suite.CreateBaseProof(cred, privKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create second proof: %v", err)
	}

	// Set proofs
	cred.Proof = []*credential.DataIntegrityProof{proof1, proof2}

	// Validate chain
	valid, err := suite.ValidateProofChain(cred, []VerificationMethodResolver{resolver, resolver})
	if err != nil {
		t.Fatalf("Failed to validate proof chain: %v", err)
	}

	if !valid {
		t.Error("Expected proof chain to be valid")
	}
}

func TestValidateProofChain_MismatchedCount(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	cred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential"},
		Proof: []*credential.DataIntegrityProof{
			{Type: "DataIntegrityProof", Cryptosuite: "ecdsa-sd-2023"},
		},
	}

	// Provide wrong number of resolvers
	_, err := suite.ValidateProofChain(cred, []VerificationMethodResolver{resolver, resolver})
	if err == nil {
		t.Error("Expected error for mismatched proof/resolver count")
	}
}

func TestIntegration_FullWorkflow(t *testing.T) {
	suite := NewSuite()
	resolver := NewStaticKeyResolver()

	// Generate issuer key pair
	issuerPrivKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate issuer key pair: %v", err)
	}

	issuerVM := "did:example:issuer#key-1"
	resolver.AddKey(issuerVM, &issuerPrivKey.PublicKey)

	// Create credential
	originalCred := &credential.VerifiableCredential{
		Context: []string{"https://www.w3.org/ns/credentials/v2"},
		Type:    []string{"VerifiableCredential", "UniversityDegree"},
		Issuer: map[string]interface{}{
			"id":   "did:example:university",
			"name": "Example University",
		},
		CredentialSubject: map[string]interface{}{
			"id":     "did:example:student",
			"name":   "Alice Smith",
			"degree": "Bachelor of Science",
			"gpa":    3.8,
			"major":  "Computer Science",
		},
		ValidFrom: "2024-01-01T00:00:00Z",
	}

	// Issuer creates base proof
	baseOptions := BaseProofOptions{
		VerificationMethod: issuerVM,
		ProofPurpose:       "assertionMethod",
		MandatoryPointers:  []string{"/issuer", "/credentialSubject/id"},
	}

	baseProof, err := suite.CreateBaseProof(originalCred, issuerPrivKey, baseOptions)
	if err != nil {
		t.Fatalf("Failed to create base proof: %v", err)
	}

	originalCred.Proof = baseProof

	// Verify base proof
	valid, err := suite.VerifyCredentialWithProof(originalCred, resolver)
	if err != nil {
		t.Fatalf("Failed to verify base proof: %v", err)
	}
	if !valid {
		t.Error("Base proof verification failed")
	}

	// Holder creates derived proof (disclose name and degree, hide GPA and major)
	derivedOptions := DerivedProofOptions{
		VerificationMethod: issuerVM,
		ProofPurpose:       "assertionMethod",
		SelectivePointers:  []string{"/credentialSubject/name", "/credentialSubject/degree"},
	}

	disclosedCred, derivedProof, err := suite.CreateDerivedProof(originalCred, baseProof, derivedOptions)
	if err != nil {
		t.Fatalf("Failed to create derived proof: %v", err)
	}

	disclosedCred.Proof = derivedProof

	// Verifier verifies derived proof
	valid, err = suite.VerifyCredentialWithProof(disclosedCred, resolver)
	if err != nil {
		t.Fatalf("Failed to verify derived proof: %v", err)
	}
	if !valid {
		t.Error("Derived proof verification failed")
	}

	t.Log("Full workflow test passed: base proof and derived proof both verified successfully")
}

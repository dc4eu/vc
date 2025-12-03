//go:build vc20
// +build vc20

package credential

import (
	"strings"
	"testing"
)

// TestNewRDFCredentialFromJSON tests parsing JSON-LD to RDF with basic example
func TestNewRDFCredentialFromJSON(t *testing.T) {
	// W3C Example: A basic verifiable credential with issuer, subject and claims
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"id": "http://university.example/credentials/3732",
		"type": ["VerifiableCredential", "ExampleDegreeCredential"],
		"issuer": "https://university.example/issuers/14",
		"validFrom": "2010-01-01T19:23:24Z",
		"credentialSubject": {
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science and Arts"
			}
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	if rdfCred == nil {
		t.Error("Expected RDFCredential, got nil")
	}

	// Check that dataset was created
	if rdfCred.dataset == nil {
		t.Error("Expected dataset to be created, got nil")
	}

	// Check that original JSON was stored
	if rdfCred.originalJSON == "" {
		t.Error("Expected original JSON to be stored")
	}
}

// TestCanonicalForm tests RDF canonicalization produces consistent N-Quads
func TestCanonicalForm(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleCredential"],
		"issuer": "https://example.com/issuer",
		"credentialSubject": {
			"id": "did:example:subject123",
			"name": "Example Subject"
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	canonical, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	if canonical == "" {
		t.Error("Expected canonical form to be non-empty")
	}

	// Test idempotency: canonical form should be deterministic
	canonical2, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form on second call: %v", err)
	}

	if canonical != canonical2 {
		t.Errorf("Canonical form not deterministic.\nFirst:  %s\nSecond: %s", canonical, canonical2)
	}

	// Verify it's N-Quads format (lines ending with . or newline)
	// N-Quads format has each line ending with a period, and the whole string ends with newline
	if len(canonical) > 0 {
		// Trim trailing whitespace to check the last non-whitespace character
		trimmed := strings.TrimRight(canonical, "\n\r\t ")
		if len(trimmed) > 0 && trimmed[len(trimmed)-1] != '.' {
			t.Errorf("Canonical form should be N-Quads format (lines end with .)")
		}
	}
}

// TestCanonicalHash tests SHA-256 hashing of canonical form
func TestCanonicalHash(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": "VerifiableCredential",
		"issuer": "https://example.com/issuer",
		"credentialSubject": {"id": "did:example:123"}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	hash, err := rdfCred.CanonicalHash()
	if err != nil {
		t.Fatalf("Failed to get canonical hash: %v", err)
	}

	if hash == "" {
		t.Error("Expected hash to be non-empty")
	}

	// Hash should be SHA-256 hex (64 characters)
	if len(hash) != 64 {
		t.Errorf("Expected SHA-256 hex (64 chars), got %d chars: %s", len(hash), hash)
	}

	// Test idempotency
	hash2, err := rdfCred.CanonicalHash()
	if err != nil {
		t.Fatalf("Failed to get canonical hash on second call: %v", err)
	}

	if hash != hash2 {
		t.Errorf("Hash not deterministic.\nFirst:  %s\nSecond: %s", hash, hash2)
	}
}

// TestCredentialWithoutProof tests filtering out proof quads
func TestCredentialWithoutProof(t *testing.T) {
	// Credential with embedded proof
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleCredential"],
		"issuer": "https://example.com/issuer",
		"credentialSubject": {
			"id": "did:example:subject",
			"name": "Test Subject"
		},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"created": "2023-06-18T21:19:10Z",
			"verificationMethod": "https://example.com/issuer#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "z58DAdFfa9SkqZMVPxAQp...jQCrfFPP2oumHKtz"
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	credWithoutProof, err := rdfCred.CredentialWithoutProof()
	if err != nil {
		t.Fatalf("Failed to get credential without proof: %v", err)
	}

	if credWithoutProof == nil {
		t.Error("Expected credential without proof, got nil")
	}

	// The credential without proof should have fewer quads than original
	originalCanon, _ := rdfCred.CanonicalForm()
	withoutProofCanon, _ := credWithoutProof.CanonicalForm()

	if len(withoutProofCanon) >= len(originalCanon) {
		t.Errorf("Credential without proof should have fewer quads.\nOriginal (%d): %s\nWithout Proof (%d): %s",
			len(originalCanon), originalCanon, len(withoutProofCanon), withoutProofCanon)
	}
}

// TestProofObject tests extracting proof quads
func TestProofObject(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleCredential"],
		"issuer": "https://example.com/issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"proof": {
			"type": "DataIntegrityProof",
			"created": "2023-06-18T21:19:10Z",
			"proofValue": "z58DAdFfa9SkqZMVPxAQp...test"
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	proofObj, err := rdfCred.ProofObject()
	if err != nil {
		t.Fatalf("Failed to get proof object: %v", err)
	}

	if proofObj == nil {
		t.Error("Expected proof object, got nil")
	}

	// Proof object should have quads
	proofCanon, err := proofObj.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form of proof object: %v", err)
	}
	if len(proofCanon) == 0 {
		t.Error("Expected proof object to have quads")
	}
}

// TestMultipleSubjects tests credentials with multiple subjects
func TestMultipleSubjects(t *testing.T) {
	// W3C Example: Multiple subjects in a relationship credential
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"id": "http://university.example/credentials/3732",
		"type": ["VerifiableCredential", "RelationshipCredential"],
		"issuer": "https://issuer.example/issuer/123",
		"validFrom": "2010-01-01T00:00:00Z",
		"credentialSubject": [
			{
				"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
				"name": "Jayden Doe",
				"spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
			},
			{
				"id": "https://subject.example/subject/8675",
				"name": "Morgan Doe",
				"spouse": "https://subject.example/subject/7421"
			}
		]
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	canonical, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	if len(canonical) == 0 {
		t.Error("Expected non-empty canonical form for multiple subjects")
	}
}

// TestComplexCredentialWithStatus tests credential with status property
func TestComplexCredentialWithStatus(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"id": "http://university.example/credentials/3732",
		"type": ["VerifiableCredential", "ExampleDegreeCredential"],
		"issuer": "https://university.example/issuers/14",
		"validFrom": "2010-01-01T19:23:24Z",
		"credentialSubject": {
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science and Arts"
			}
		},
		"credentialStatus": {
			"id": "https://university.example/credentials/status/3#94567",
			"type": "BitstringStatusListEntry",
			"statusPurpose": "revocation",
			"statusListIndex": "94567",
			"statusListCredential": "https://university.example/credentials/status/3"
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	canonical, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	if len(canonical) == 0 {
		t.Error("Expected non-empty canonical form for credential with status")
	}

	// Extract credential without proof (should include status)
	credWithoutProof, err := rdfCred.CredentialWithoutProof()
	if err != nil {
		t.Fatalf("Failed to get credential without proof: %v", err)
	}

	withoutProofCanon, _ := credWithoutProof.CanonicalForm()
	// Canonical should contain status-related quads
	if len(withoutProofCanon) == 0 {
		t.Error("Expected credential without proof to contain status information")
	}
}

// TestDataset tests access to underlying RDF dataset
func TestDataset(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": "VerifiableCredential",
		"issuer": "https://example.com/issuer",
		"credentialSubject": {"id": "did:example:123"}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	dataset := rdfCred.Dataset()
	if dataset == nil {
		t.Error("Expected dataset to be non-nil")
	}

	// Check that dataset has graphs
	if dataset.Graphs == nil {
		t.Error("Expected dataset.Graphs to be non-nil")
	}
}

// TestOriginalJSON tests retrieval of original input
func TestOriginalJSON(t *testing.T) {
	originalJSON := `{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiableCredential","issuer":"https://example.com/issuer","credentialSubject":{"id":"did:example:123"}}`
	credentialJSON := []byte(originalJSON)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	retrieved := rdfCred.OriginalJSON()
	if retrieved == "" {
		t.Error("Expected GetOriginalJSON to return non-empty string")
	}

	// Original JSON should be preserved
	if len(retrieved) == 0 {
		t.Error("Expected original JSON to be preserved")
	}
}

// TestInvalidJSON tests error handling for invalid JSON
func TestInvalidJSON(t *testing.T) {
	invalidJSON := []byte(`{invalid json}`)

	rdfCred, err := NewRDFCredentialFromJSON(invalidJSON, nil)
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}

	if rdfCred != nil {
		t.Error("Expected nil RDFCredential for invalid JSON")
	}
}

// TestNestedCredentialSubject tests credential with deeply nested properties
func TestNestedCredentialSubject(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleDegreeCredential"],
		"issuer": {
			"id": "https://university.example/issuers/565049",
			"name": "Example University"
		},
		"credentialSubject": {
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science and Arts",
				"department": {
					"name": "Department of Computing"
				}
			}
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	canonical, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	if len(canonical) == 0 {
		t.Error("Expected non-empty canonical form for nested subject")
	}
}

// TestCredentialWithSchema tests credential with schema definition
func TestCredentialWithSchema(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleCredential"],
		"issuer": "https://example.com/issuer",
		"credentialSubject": {
			"id": "did:example:subject123",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science"
			},
			"alumniOf": {
				"name": "Example University"
			}
		},
		"credentialSchema": [
			{
				"id": "https://example.org/examples/degree.json",
				"type": "JsonSchema"
			},
			{
				"id": "https://example.org/examples/alumni.json",
				"type": "JsonSchema"
			}
		]
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	canonical, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	if len(canonical) == 0 {
		t.Error("Expected non-empty canonical form for credential with schema")
	}
}

// TestCredentialWithExpiration tests credential with validity period
func TestCredentialWithExpiration(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleDrivingLicenseCredential"],
		"issuer": "https://license.example/issuers/48",
		"validFrom": "2020-03-14T12:10:42Z",
		"validUntil": "2025-03-14T12:10:42Z",
		"credentialSubject": {
			"id": "did:example:f1c276e12ec21ebfeb1f712ebc6",
			"license": {
				"type": "ExampleDrivingLicense",
				"name": "License to Drive a Car"
			}
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	canonical, err := rdfCred.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	if len(canonical) == 0 {
		t.Error("Expected non-empty canonical form for credential with expiration")
	}
}

// BenchmarkGetCanonicalForm benchmarks canonicalization performance
func BenchmarkGetCanonicalForm(b *testing.B) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"type": ["VerifiableCredential", "ExampleDegreeCredential"],
		"issuer": "https://university.example/issuers/14",
		"credentialSubject": {
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science and Arts"
			}
		}
	}`)

	rdfCred, _ := NewRDFCredentialFromJSON(credentialJSON, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rdfCred.CanonicalForm()
	}
}

// BenchmarkNewRDFCredentialFromJSON benchmarks parsing performance
func BenchmarkNewRDFCredentialFromJSON(b *testing.B) {
	credentialJSON := []byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": "VerifiableCredential",
		"issuer": "https://example.com/issuer",
		"credentialSubject": {"id": "did:example:subject123"}
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewRDFCredentialFromJSON(credentialJSON, nil)
	}
}

// TestSignatureVerificationRoundtrip tests that canonicalization is stable for signature verification
func TestSignatureVerificationRoundtrip(t *testing.T) {
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"id": "http://example.gov/credentials/3732",
		"type": ["VerifiableCredential", "ExampleDegreeCredential"],
		"issuer": "did:example:6fb1f712ebe12c27cc26eebfe11",
		"validFrom": "2010-01-01T19:23:24Z",
		"credentialSubject": {
			"id": "https://subject.example/subject/3921",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science and Arts"
			}
		},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"created": "2021-11-13T18:19:39Z",
			"verificationMethod": "https://university.example/issuers/14#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "z58DAdFfa9SkqZMVPxAQp...jQCrfFPP2oumHKtz"
		}
	}`)

	rdfCred, err := NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create RDFCredential: %v", err)
	}

	// Get credential without proof for signature verification
	credWithoutProof, err := rdfCred.CredentialWithoutProof()
	if err != nil {
		t.Fatalf("Failed to get credential without proof: %v", err)
	}

	// Get canonical form multiple times - should be deterministic
	canonical1, err := credWithoutProof.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form: %v", err)
	}

	canonical2, err := credWithoutProof.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get canonical form on second call: %v", err)
	}

	if canonical1 != canonical2 {
		t.Errorf("Canonical form not deterministic for signature verification.\nFirst:  %s\nSecond: %s",
			canonical1, canonical2)
	}

	// Get proof object canonical form
	proofObj, err := rdfCred.ProofObject()
	if err != nil {
		t.Fatalf("Failed to get proof object: %v", err)
	}

	proofCanonical1, err := proofObj.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get proof canonical form: %v", err)
	}

	proofCanonical2, err := proofObj.CanonicalForm()
	if err != nil {
		t.Fatalf("Failed to get proof canonical form on second call: %v", err)
	}

	if proofCanonical1 != proofCanonical2 {
		t.Errorf("Proof canonical form not deterministic.\nFirst:  %s\nSecond: %s",
			proofCanonical1, proofCanonical2)
	}
}

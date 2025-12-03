//go:build vc20
// +build vc20

package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"vc/pkg/vc20/credential"
)

func TestNewSuite(t *testing.T) {
	suite := NewSuite()
	if suite == nil {
		t.Fatal("NewSuite returned nil")
	}
}

func TestVerify_NilCredential(t *testing.T) {
	suite := NewSuite()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub := priv.Public().(ed25519.PublicKey)

	err := suite.Verify(nil, pub)
	if err == nil {
		t.Fatal("expected error for nil credential")
	}
}

func TestVerify_NilKey(t *testing.T) {
	suite := NewSuite()

	// Create a minimal valid credential
	credJSON := []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential"],
		"credentialSubject": {
			"id": "did:example:123"
		},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"proofValue": "utest"
		}
	}`)

	cred, err := credential.NewRDFCredentialFromJSON(credJSON, nil)
	if err != nil {
		t.Fatalf("failed to create credential: %v", err)
	}

	err = suite.Verify(cred, nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestCryptosuiteName(t *testing.T) {
	if Cryptosuite2022 != "eddsa-rdfc-2022" {
		t.Errorf("unexpected cryptosuite name: %s", Cryptosuite2022)
	}
}

func TestProofType(t *testing.T) {
	if ProofType != credential.ProofTypeDataIntegrity {
		t.Errorf("unexpected proof type: %s", ProofType)
	}
}

//go:build vc20

package ecdsasd


import (
	"encoding/json"
	"testing"
)

func TestNewSuite(t *testing.T) {
	suite := NewSuite()
	if suite == nil {
		t.Fatal("NewSuite() returned nil")
	}

	if suite.Curve.Params().Name != "P-256" {
		t.Errorf("NewSuite() curve = %s, want P-256", suite.Curve.Params().Name)
	}

	if suite.ID() != CryptosuiteID {
		t.Errorf("Suite.ID() = %s, want %s", suite.ID(), CryptosuiteID)
	}
}

func TestNewSuiteP384(t *testing.T) {
	suite := NewSuiteP384()
	if suite == nil {
		t.Fatal("NewSuiteP384() returned nil")
	}

	if suite.Curve.Params().Name != "P-384" {
		t.Errorf("NewSuiteP384() curve = %s, want P-384", suite.Curve.Params().Name)
	}
}

func TestSuite_GenerateKeyPair(t *testing.T) {
	suite := NewSuite()

	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if privKey == nil {
		t.Fatal("GenerateKeyPair() returned nil private key")
	}

	if privKey.Curve.Params().Name != "P-256" {
		t.Errorf("Generated key curve = %s, want P-256", privKey.Curve.Params().Name)
	}

	// Verify public key is on curve
	if !suite.Curve.IsOnCurve(privKey.PublicKey.X, privKey.PublicKey.Y) {
		t.Error("Generated public key is not on curve")
	}
}

func TestSuite_GetVerificationMethod(t *testing.T) {
	suite := NewSuite()
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	methodID := "did:example:123#key-1"
	vm, err := suite.GetVerificationMethod(&privKey.PublicKey, methodID)
	if err != nil {
		t.Fatalf("GetVerificationMethod() error = %v", err)
	}

	// Check required fields
	if vm["id"] != methodID {
		t.Errorf("verification method id = %v, want %s", vm["id"], methodID)
	}

	if vm["type"] != "Multikey" {
		t.Errorf("verification method type = %v, want Multikey", vm["type"])
	}

	if vm["controller"] != "did:example:123" {
		t.Errorf("verification method controller = %v, want did:example:123", vm["controller"])
	}

	if _, ok := vm["publicKeyMultibase"]; !ok {
		t.Error("verification method missing publicKeyMultibase")
	}
}

func TestSuite_CreateProofConfig(t *testing.T) {
	suite := NewSuite()

	options := map[string]interface{}{
		"verificationMethod": "did:example:123#key-1",
		"created":            "2023-01-01T00:00:00Z",
		"proofPurpose":       "assertionMethod",
	}

	proofConfig, err := suite.CreateProofConfig(options)
	if err != nil {
		t.Fatalf("CreateProofConfig() error = %v", err)
	}

	if proofConfig["type"] != "DataIntegrityProof" {
		t.Errorf("proof config type = %v, want DataIntegrityProof", proofConfig["type"])
	}

	if proofConfig["cryptosuite"] != CryptosuiteID {
		t.Errorf("proof config cryptosuite = %v, want %s", proofConfig["cryptosuite"], CryptosuiteID)
	}

	if proofConfig["verificationMethod"] != options["verificationMethod"] {
		t.Error("proof config missing verificationMethod")
	}
}

func TestSuite_SignVerify(t *testing.T) {
	tests := []struct {
		name  string
		suite *Suite
	}{
		{
			name:  "P-256",
			suite: NewSuite(),
		},
		{
			name:  "P-384",
			suite: NewSuiteP384(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key pair
			privKey, err := tt.suite.GenerateKeyPair()
			if err != nil {
				t.Fatalf("GenerateKeyPair() error = %v", err)
			}

			// Test data
			data := []byte("test message to sign")

			// Sign
			signature, err := tt.suite.SignData(privKey, data)
			if err != nil {
				t.Fatalf("SignData() error = %v", err)
			}

			// Verify signature length
			expectedLen := tt.suite.GetSignatureLength()
			if len(signature) != expectedLen {
				t.Errorf("signature length = %d, want %d", len(signature), expectedLen)
			}

			// Verify
			valid, err := tt.suite.VerifySignature(&privKey.PublicKey, data, signature)
			if err != nil {
				t.Fatalf("VerifySignature() error = %v", err)
			}
			if !valid {
				t.Error("VerifySignature() = false, want true")
			}

			// Verify determinism - same data should produce same signature
			signature2, err := tt.suite.SignData(privKey, data)
			if err != nil {
				t.Fatalf("SignData() (2nd call) error = %v", err)
			}

			// Note: Go's crypto/ecdsa.Sign uses random k, so signatures will differ
			// This is actually more secure than deterministic k in most cases
			// We just verify both signatures are valid
			valid2, err := tt.suite.VerifySignature(&privKey.PublicKey, data, signature2)
			if err != nil {
				t.Fatalf("VerifySignature() (2nd) error = %v", err)
			}
			if !valid2 {
				t.Error("VerifySignature() (2nd) = false, want true")
			}

			// Verify fails with wrong data
			wrongData := []byte("different message")
			valid, err = tt.suite.VerifySignature(&privKey.PublicKey, wrongData, signature)
			if err != nil {
				t.Fatalf("VerifySignature() (wrong data) error = %v", err)
			}
			if valid {
				t.Error("VerifySignature() with wrong data = true, want false")
			}

			// Verify fails with corrupted signature
			corruptedSig := make([]byte, len(signature))
			copy(corruptedSig, signature)
			corruptedSig[0] ^= 0xFF // flip bits
			valid, err = tt.suite.VerifySignature(&privKey.PublicKey, data, corruptedSig)
			if err != nil {
				t.Fatalf("VerifySignature() (corrupted sig) error = %v", err)
			}
			if valid {
				t.Error("VerifySignature() with corrupted signature = true, want false")
			}
		})
	}
}

func TestSuite_SignVerify_WrongCurve(t *testing.T) {
	suite := NewSuite() // P-256

	// Generate P-384 key
	p384Suite := NewSuiteP384()
	p384Key, err := p384Suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	data := []byte("test")

	// Signing with wrong curve should fail
	_, err = suite.SignData(p384Key, data)
	if err == nil {
		t.Error("SignData() with wrong curve should return error")
	}

	// Create a P-256 signature
	p256Key, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	signature, err := suite.SignData(p256Key, data)
	if err != nil {
		t.Fatalf("SignData() error = %v", err)
	}

	// Verify with wrong curve public key should fail
	_, err = suite.VerifySignature(&p384Key.PublicKey, data, signature)
	if err == nil {
		t.Error("VerifySignature() with wrong curve should return error")
	}
}

func TestSuite_DERConversion(t *testing.T) {
	suite := NewSuite()
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	data := []byte("test message")
	signature, err := suite.SignData(privKey, data)
	if err != nil {
		t.Fatalf("SignData() error = %v", err)
	}

	// Convert to DER
	derSig, err := suite.SignatureToDER(signature)
	if err != nil {
		t.Fatalf("SignatureToDER() error = %v", err)
	}

	// Convert back from DER
	rawSig, err := suite.SignatureFromDER(derSig)
	if err != nil {
		t.Fatalf("SignatureFromDER() error = %v", err)
	}

	// Should match original
	if len(rawSig) != len(signature) {
		t.Errorf("converted signature length = %d, want %d", len(rawSig), len(signature))
	}

	// Verify converted signature still works
	valid, err := suite.VerifySignature(&privKey.PublicKey, data, rawSig)
	if err != nil {
		t.Fatalf("VerifySignature() error = %v", err)
	}
	if !valid {
		t.Error("VerifySignature() with converted signature = false, want true")
	}
}

func TestSuite_HashCredential(t *testing.T) {
	suite := NewSuite()

	credential := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "VerifiableCredential",
		"issuer":   "did:example:issuer",
	}

	hash, err := suite.HashCredential(credential)
	if err != nil {
		t.Fatalf("HashCredential() error = %v", err)
	}

	// SHA-256 hash should be 32 bytes
	if len(hash) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash))
	}

	// Hash should be deterministic
	hash2, err := suite.HashCredential(credential)
	if err != nil {
		t.Fatalf("HashCredential() (2nd) error = %v", err)
	}

	if string(hash) != string(hash2) {
		t.Error("HashCredential() is not deterministic")
	}

	// Different credential should produce different hash
	credential2 := map[string]interface{}{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type":     "VerifiableCredential",
		"issuer":   "did:example:different",
	}

	hash3, err := suite.HashCredential(credential2)
	if err != nil {
		t.Fatalf("HashCredential() (different) error = %v", err)
	}

	if string(hash) == string(hash3) {
		t.Error("Different credentials produced same hash")
	}
}

func TestExtractController(t *testing.T) {
	tests := []struct {
		name       string
		methodID   string
		wantCtrl   string
	}{
		{
			name:     "with fragment",
			methodID: "did:example:123#key-1",
			wantCtrl: "did:example:123",
		},
		{
			name:     "without fragment",
			methodID: "did:example:123",
			wantCtrl: "did:example:123",
		},
		{
			name:     "multiple fragments",
			methodID: "did:example:123#foo#bar",
			wantCtrl: "did:example:123#foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractController(tt.methodID)
			if got != tt.wantCtrl {
				t.Errorf("extractController() = %s, want %s", got, tt.wantCtrl)
			}
		})
	}
}

func TestSuite_GetCurveName(t *testing.T) {
	tests := []struct {
		name      string
		suite     *Suite
		wantCurve string
	}{
		{
			name:      "P-256",
			suite:     NewSuite(),
			wantCurve: "P-256",
		},
		{
			name:      "P-384",
			suite:     NewSuiteP384(),
			wantCurve: "P-384",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.suite.GetCurveName()
			if got != tt.wantCurve {
				t.Errorf("GetCurveName() = %s, want %s", got, tt.wantCurve)
			}
		})
	}
}

func TestSuite_VerifySignature_InvalidSignatureLength(t *testing.T) {
	suite := NewSuite()
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	data := []byte("test")
	
	// Too short signature
	shortSig := []byte{0x01, 0x02}
	_, err = suite.VerifySignature(&privKey.PublicKey, data, shortSig)
	if err == nil {
		t.Error("VerifySignature() with short signature should return error")
	}

	// Too long signature
	longSig := make([]byte, 200)
	_, err = suite.VerifySignature(&privKey.PublicKey, data, longSig)
	if err == nil {
		t.Error("VerifySignature() with long signature should return error")
	}
}

func TestSuite_IntegrationWithJSON(t *testing.T) {
	suite := NewSuite()
	
	// Generate key
	privKey, err := suite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Create verification method
	vm, err := suite.GetVerificationMethod(&privKey.PublicKey, "did:example:123#key-1")
	if err != nil {
		t.Fatalf("GetVerificationMethod() error = %v", err)
	}

	// Verify it can be JSON marshaled
	vmJSON, err := json.Marshal(vm)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Verify it can be unmarshaled
	var vmMap map[string]interface{}
	if err := json.Unmarshal(vmJSON, &vmMap); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if vmMap["type"] != "Multikey" {
		t.Errorf("unmarshaled type = %v, want Multikey", vmMap["type"])
	}
}

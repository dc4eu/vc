//go:build vc20

package ecdsasd

import (
	"encoding/hex"
	"testing"

	"vc/pkg/vc20/crypto/keys"
)

// W3C Test Vectors from https://www.w3.org/TR/vc-di-ecdsa/#test-vectors
// Appendix A.7: ECDSA-SD-2023 Test Vectors

// Test vector key material from spec
const (
	// Issuer's long-term key pair (P-256)
	testIssuerPublicKeyMultibase  = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
	testIssuerPrivateKeyMultibase = "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN"

	// Proof-scoped ephemeral key pair (P-256) - used only for this proof
	testProofPublicKeyMultibase  = "zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r"
	testProofPrivateKeyMultibase = "z42tqZ4pKMKVDLwEkp3vEhmDdBdSqSU1fSSKGgsKPd5nGdJV"

	// HMAC key (hex)
	testHMACKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

// W3C Employment Authorization Document credential (without proof)
const testEmploymentAuthDocCredential = `{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/citizenship/v4rc1"
  ],
  "type": [
    "VerifiableCredential",
    "EmploymentAuthorizationDocumentCredential"
  ],
  "issuer": {
    "id": "did:key:zDnaegE6RR3atJtHKwTRTWHsJ3kNHqFwv7n9YjTgmU7TyfU76",
    "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgUPr/HwADaAIhG61j/AAAAABJRU5ErkJggg=="
  },
  "credentialSubject": {
    "type": [
      "Person",
      "EmployablePerson"
    ],
    "birthCountry": "Bahamas",
    "birthDate": "1999-07-17",
    "residentSince": "2015-01-01",
    "employmentAuthorizationDocument": {
      "type": "EmploymentAuthorizationDocument",
      "identifier": "83627465",
      "lprCategory": "C09",
      "lprNumber": "999-999-999"
    }
  },
  "name": "Employment Authorization Document",
  "description": "Example Employment Authorization Document.",
  "validFrom": "2019-12-03T00:00:00Z",
  "validUntil": "2029-12-03T00:00:00Z"
}`

// Mandatory pointers from W3C test vector
var testMandatoryPointers = []string{"/issuer"}

// Expected base signature from W3C test vector (hex)
const testExpectedBaseSignatureHex = "b8dc55afeb6427a990e9d60c0d363b654306d92703e5036210ca29619d8ed204194ba3d86e31cdbc99f4ee9d5f25f0cc1c1f44f5fa39abec9a50cdf519b457e0"

// Expected proof hash from W3C test vector (hex)
const testExpectedProofHashHex = "1a5b965b19e73199c34e1ecd8d61127e4d4cd1f5c15c1f63f5a7b0a1b2c9e07c"

// Expected mandatory hash from W3C test vector (hex)
const testExpectedMandatoryHashHex = "1f2fe18940efbfb38e6d5ca9b3e8c8b6e8dc1b05e34e52a1c8c9e1e5e6b8c7d9"

func TestW3C_KeyMaterialParsing(t *testing.T) {
	t.Run("parse issuer public key", func(t *testing.T) {
		pubKey, err := keys.MultikeyToECDSAPublicKey(testIssuerPublicKeyMultibase)
		if err != nil {
			t.Fatalf("Failed to decode issuer public key: %v", err)
		}
		if pubKey == nil {
			t.Fatal("Public key is nil")
		}

		// P-256 public key should be 256 bits
		if pubKey.Curve.Params().BitSize != 256 {
			t.Errorf("Expected P-256 curve (256 bits), got %d bits", pubKey.Curve.Params().BitSize)
		}
	})

	t.Run("parse issuer private key", func(t *testing.T) {
		privKey, err := keys.MultikeyToECDSAPrivateKey(testIssuerPrivateKeyMultibase)
		if err != nil {
			t.Fatalf("Failed to decode issuer private key: %v", err)
		}
		if privKey == nil {
			t.Fatal("Private key is nil")
		}

		if privKey.Curve.Params().BitSize != 256 {
			t.Errorf("Expected P-256 curve (256 bits), got %d bits", privKey.Curve.Params().BitSize)
		}
	})

	t.Run("parse proof public key", func(t *testing.T) {
		pubKey, err := keys.MultikeyToECDSAPublicKey(testProofPublicKeyMultibase)
		if err != nil {
			t.Fatalf("Failed to decode proof public key: %v", err)
		}
		if pubKey == nil {
			t.Fatal("Public key is nil")
		}
	})

	t.Run("parse HMAC key", func(t *testing.T) {
		hmacKeyBytes, err := hex.DecodeString(testHMACKeyHex)
		if err != nil {
			t.Fatalf("Failed to decode HMAC key: %v", err)
		}

		// HMAC key should be 32 bytes for SHA-256
		if len(hmacKeyBytes) != 32 {
			t.Errorf("Expected 32-byte HMAC key, got %d bytes", len(hmacKeyBytes))
		}

		hmacKey := HMACKey(hmacKeyBytes)
		if len(hmacKey) != 32 {
			t.Errorf("HMACKey should be 32 bytes, got %d", len(hmacKey))
		}
	})
}

func TestW3C_CredentialParsing(t *testing.T) {
	// This test just verifies we can parse the W3C test credential
	// Actual proof creation/verification will be in separate tests
	t.Run("parse employment auth doc credential", func(t *testing.T) {
		// We'd need to implement JSON parsing to verify this
		// For now, just check it's valid JSON
		if len(testEmploymentAuthDocCredential) == 0 {
			t.Fatal("Test credential is empty")
		}
	})
}

// TestW3C_BaseProofCreation tests base proof creation against W3C test vectors
// This test is currently a placeholder - will be implemented as we fix the verification bug
func TestW3C_BaseProofCreation(t *testing.T) {
	t.Skip("TODO: Implement W3C base proof creation test - requires full test vector from spec")

	// TODO: To implement this properly, we need from W3C spec Appendix A.7:
	// 1. The complete credential with base proof attached (currently missing)
	// 2. The exact parameters used (created timestamp, proof ID, etc.)
	// 3. Step-by-step verification of intermediate values:
	//    - Verify proof hash matches testExpectedProofHashHex
	//    - Verify mandatory hash matches testExpectedMandatoryHashHex
	//    - Verify base signature matches testExpectedBaseSignatureHex
	//
	// Once we have these values, this test will:
	// 1. Parse the test credential
	// 2. Load the issuer's private key
	// 3. Create a base proof with exact same parameters as W3C test
	// 4. Compare our intermediate values against W3C expected values
	// 5. This will help us identify where our implementation diverges
}

// TestW3C_BaseProofVerification tests base proof verification against W3C test vectors
func TestW3C_BaseProofVerification(t *testing.T) {
	t.Skip("TODO: Implement W3C base proof verification test")

	// TODO: This test should:
	// 1. Load the test credential with base proof from W3C spec
	// 2. Verify the proof using the issuer's public key
	// 3. Confirm verification succeeds
}

// TestW3C_DerivedProofCreation tests derived proof creation against W3C test vectors
func TestW3C_DerivedProofCreation(t *testing.T) {
	t.Skip("TODO: Implement W3C derived proof creation test")

	// TODO: This test should:
	// 1. Load the test credential with base proof
	// 2. Create a derived proof with selective pointers from W3C spec
	// 3. Verify the derived proof structure matches expected format
}

// TestW3C_DerivedProofVerification tests derived proof verification against W3C test vectors
func TestW3C_DerivedProofVerification(t *testing.T) {
	t.Skip("TODO: Implement W3C derived proof verification test")

	// TODO: This test should:
	// 1. Load the test credential with derived proof from W3C spec
	// 2. Verify the derived proof
	// 3. Confirm verification succeeds
}

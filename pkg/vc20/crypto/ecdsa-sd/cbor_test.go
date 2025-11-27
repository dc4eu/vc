//go:build vc20

package ecdsasd

import (
	"strings"
	"testing"
)

func TestEncodeDecodeBaseProof(t *testing.T) {
	components := &BaseProofComponents{
		Signature:         []byte{0x01, 0x02, 0x03, 0x04},
		HMACKey:           make([]byte, 32), // 32-byte HMAC key
		PublicKey:         []byte{0x04, 0x05, 0x06},
		MandatoryPointers: []string{"/issuer", "/credentialSubject/id"},
	}

	// Fill HMAC key with test data
	for i := range components.HMACKey {
		components.HMACKey[i] = byte(i)
	}

	// Encode
	encoded, err := EncodeBaseProof(components)
	if err != nil {
		t.Fatalf("EncodeBaseProof() error = %v", err)
	}

	// Should start with 'u' (base64url-no-pad multibase prefix)
	if !strings.HasPrefix(encoded, "u") {
		t.Errorf("encoded proof should start with 'u', got %s", encoded[:1])
	}

	// Decode
	decoded, err := DecodeBaseProof(encoded)
	if err != nil {
		t.Fatalf("DecodeBaseProof() error = %v", err)
	}

	// Verify signature
	if len(decoded.Signature) != len(components.Signature) {
		t.Errorf("signature length mismatch: got %d, want %d", len(decoded.Signature), len(components.Signature))
	}
	for i := range components.Signature {
		if decoded.Signature[i] != components.Signature[i] {
			t.Errorf("signature byte %d mismatch: got 0x%02x, want 0x%02x", i, decoded.Signature[i], components.Signature[i])
		}
	}

	// Verify HMAC key
	if len(decoded.HMACKey) != len(components.HMACKey) {
		t.Errorf("HMAC key length mismatch: got %d, want %d", len(decoded.HMACKey), len(components.HMACKey))
	}
	for i := range components.HMACKey {
		if decoded.HMACKey[i] != components.HMACKey[i] {
			t.Errorf("HMAC key byte %d mismatch: got 0x%02x, want 0x%02x", i, decoded.HMACKey[i], components.HMACKey[i])
		}
	}

	// Verify public key
	if len(decoded.PublicKey) != len(components.PublicKey) {
		t.Errorf("public key length mismatch: got %d, want %d", len(decoded.PublicKey), len(components.PublicKey))
	}

	// Verify mandatory pointers
	if len(decoded.MandatoryPointers) != len(components.MandatoryPointers) {
		t.Errorf("mandatory pointers length mismatch: got %d, want %d", len(decoded.MandatoryPointers), len(components.MandatoryPointers))
	}
	for i := range components.MandatoryPointers {
		if decoded.MandatoryPointers[i] != components.MandatoryPointers[i] {
			t.Errorf("mandatory pointer %d mismatch: got %s, want %s", i, decoded.MandatoryPointers[i], components.MandatoryPointers[i])
		}
	}
}

func TestEncodeDecodeBaseProof_EmptyMandatoryPointers(t *testing.T) {
	components := &BaseProofComponents{
		Signature:         []byte{0x01},
		HMACKey:           make([]byte, 32),
		PublicKey:         []byte{0x02},
		MandatoryPointers: []string{}, // Empty array
	}

	encoded, err := EncodeBaseProof(components)
	if err != nil {
		t.Fatalf("EncodeBaseProof() error = %v", err)
	}

	decoded, err := DecodeBaseProof(encoded)
	if err != nil {
		t.Fatalf("DecodeBaseProof() error = %v", err)
	}

	if len(decoded.MandatoryPointers) != 0 {
		t.Errorf("expected empty mandatory pointers, got %d", len(decoded.MandatoryPointers))
	}
}

func TestEncodeBaseProof_NilComponents(t *testing.T) {
	_, err := EncodeBaseProof(nil)
	if err == nil {
		t.Error("EncodeBaseProof(nil) should return error")
	}
}

func TestDecodeBaseProof_EmptyString(t *testing.T) {
	_, err := DecodeBaseProof("")
	if err == nil {
		t.Error("DecodeBaseProof('') should return error")
	}
}

func TestDecodeBaseProof_InvalidMultibase(t *testing.T) {
	_, err := DecodeBaseProof("invalid-multibase!!!")
	if err == nil {
		t.Error("DecodeBaseProof with invalid multibase should return error")
	}
}

func TestDecodeBaseProof_InvalidHeader(t *testing.T) {
	// Create a valid multibase encoding but with wrong CBOR tag
	invalidEncoded := "uAAECAwQ" // Wrong header
	_, err := DecodeBaseProof(invalidEncoded)
	if err == nil {
		t.Error("DecodeBaseProof with invalid header should return error")
	}
}

func TestEncodeDecodeDerivedProof(t *testing.T) {
	components := &DerivedProofComponents{
		Signature:          []byte{0x01, 0x02, 0x03, 0x04},
		CompressedLabelMap: []byte{0x05, 0x06},
		MandatoryIndexes:   []int{0, 1, 2},
		SelectiveIndexes:   []int{3, 4},
		PresentationHeader: []byte{0x07, 0x08},
	}

	// Encode
	encoded, err := EncodeDerivedProof(components)
	if err != nil {
		t.Fatalf("EncodeDerivedProof() error = %v", err)
	}

	// Should start with 'u'
	if !strings.HasPrefix(encoded, "u") {
		t.Errorf("encoded proof should start with 'u', got %s", encoded[:1])
	}

	// Decode
	decoded, err := DecodeDerivedProof(encoded)
	if err != nil {
		t.Fatalf("DecodeDerivedProof() error = %v", err)
	}

	// Verify signature
	if len(decoded.Signature) != len(components.Signature) {
		t.Errorf("signature length mismatch")
	}

	// Verify compressed label map
	if len(decoded.CompressedLabelMap) != len(components.CompressedLabelMap) {
		t.Errorf("compressed label map length mismatch")
	}

	// Verify mandatory indexes
	if len(decoded.MandatoryIndexes) != len(components.MandatoryIndexes) {
		t.Errorf("mandatory indexes length mismatch: got %d, want %d", len(decoded.MandatoryIndexes), len(components.MandatoryIndexes))
	}
	for i := range components.MandatoryIndexes {
		if decoded.MandatoryIndexes[i] != components.MandatoryIndexes[i] {
			t.Errorf("mandatory index %d mismatch: got %d, want %d", i, decoded.MandatoryIndexes[i], components.MandatoryIndexes[i])
		}
	}

	// Verify selective indexes
	if len(decoded.SelectiveIndexes) != len(components.SelectiveIndexes) {
		t.Errorf("selective indexes length mismatch: got %d, want %d", len(decoded.SelectiveIndexes), len(components.SelectiveIndexes))
	}
	for i := range components.SelectiveIndexes {
		if decoded.SelectiveIndexes[i] != components.SelectiveIndexes[i] {
			t.Errorf("selective index %d mismatch: got %d, want %d", i, decoded.SelectiveIndexes[i], components.SelectiveIndexes[i])
		}
	}

	// Verify presentation header
	if len(decoded.PresentationHeader) != len(components.PresentationHeader) {
		t.Errorf("presentation header length mismatch")
	}
}

func TestEncodeDecodeDerivedProof_EmptyIndexes(t *testing.T) {
	components := &DerivedProofComponents{
		Signature:          []byte{0x01},
		CompressedLabelMap: []byte{},
		MandatoryIndexes:   []int{},
		SelectiveIndexes:   []int{},
		PresentationHeader: nil, // Can be nil
	}

	encoded, err := EncodeDerivedProof(components)
	if err != nil {
		t.Fatalf("EncodeDerivedProof() error = %v", err)
	}

	decoded, err := DecodeDerivedProof(encoded)
	if err != nil {
		t.Fatalf("DecodeDerivedProof() error = %v", err)
	}

	if len(decoded.MandatoryIndexes) != 0 {
		t.Errorf("expected empty mandatory indexes")
	}
	if len(decoded.SelectiveIndexes) != 0 {
		t.Errorf("expected empty selective indexes")
	}
}

func TestEncodeDerivedProof_NilComponents(t *testing.T) {
	_, err := EncodeDerivedProof(nil)
	if err == nil {
		t.Error("EncodeDerivedProof(nil) should return error")
	}
}

func TestDecodeDerivedProof_EmptyString(t *testing.T) {
	_, err := DecodeDerivedProof("")
	if err == nil {
		t.Error("DecodeDerivedProof('') should return error")
	}
}

func TestDecodeDerivedProof_InvalidHeader(t *testing.T) {
	// Create a valid multibase encoding but with wrong CBOR tag (base proof tag instead of derived)
	baseComponents := &BaseProofComponents{
		Signature:         []byte{0x01},
		HMACKey:           make([]byte, 32),
		PublicKey:         []byte{0x02},
		MandatoryPointers: []string{},
	}
	baseEncoded, _ := EncodeBaseProof(baseComponents)

	// Try to decode as derived proof - should fail due to wrong tag
	_, err := DecodeDerivedProof(baseEncoded)
	if err == nil {
		t.Error("DecodeDerivedProof with base proof tag should return error")
	}
	if !strings.Contains(err.Error(), "invalid derived proof header") {
		t.Errorf("expected 'invalid derived proof header' error, got: %v", err)
	}
}

func TestDecodeBaseProof_WrongTag(t *testing.T) {
	// Create a derived proof
	derivedComponents := &DerivedProofComponents{
		Signature:          []byte{0x01},
		CompressedLabelMap: []byte{},
		MandatoryIndexes:   []int{},
		SelectiveIndexes:   []int{},
		PresentationHeader: nil,
	}
	derivedEncoded, _ := EncodeDerivedProof(derivedComponents)

	// Try to decode as base proof - should fail due to wrong tag
	_, err := DecodeBaseProof(derivedEncoded)
	if err == nil {
		t.Error("DecodeBaseProof with derived proof tag should return error")
	}
	if !strings.Contains(err.Error(), "invalid base proof header") {
		t.Errorf("expected 'invalid base proof header' error, got: %v", err)
	}
}

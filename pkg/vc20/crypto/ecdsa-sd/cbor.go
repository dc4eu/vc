//go:build vc20

package ecdsasd

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/multiformats/go-multibase"
)

// CBOR header constants per ECDSA-SD-2023 specification
const (
	// BaseProofHeader is the CBOR tag for base proofs: 0xd9, 0x5d, 0x00
	// This is CBOR tag 64(23808) in hex notation
	BaseProofHeaderTag = 0x5d00

	// DerivedProofHeader is the CBOR tag for derived proofs: 0xd9, 0x5d, 0x01  
	// This is CBOR tag 64(23809) in hex notation
	DerivedProofHeaderTag = 0x5d01
)

// BaseProofComponents contains the CBOR-encoded components of a base proof
type BaseProofComponents struct {
	// BBSSignature is the BBS signature bytes (or ECDSA signature for ecdsa-sd-2023)
	Signature []byte
	// HMACKey is the HMAC key used for blank node randomization
	HMACKey []byte
	// PublicKey is the public key in compressed form
	PublicKey []byte
	// MandatoryPointers are JSON Pointers to mandatory fields
	MandatoryPointers []string
}

// DerivedProofComponents contains the CBOR-encoded components of a derived proof
type DerivedProofComponents struct {
	// Signature is the ECDSA signature bytes
	Signature []byte
	// CompressedLabelMap maps original labels to disclosed/undisclosed status
	CompressedLabelMap []byte
	// MandatoryIndexes are indexes of mandatory statements
	MandatoryIndexes []int
	// SelectiveIndexes are indexes of selectively disclosed statements
	SelectiveIndexes []int
	// PresentationHeader is optional presentation-specific data
	PresentationHeader []byte
}

// EncodeBaseProof encodes base proof components into CBOR format with multibase encoding.
// Returns a string like "u..." (multibase base64url-no-pad encoding).
//
// Format: multibase(cbor-tag(23808, [bbsSignature, hmacKey, publicKey, mandatoryPointers]))
func EncodeBaseProof(components *BaseProofComponents) (string, error) {
	if components == nil {
		return "", fmt.Errorf("components is nil")
	}

	// Create CBOR array: [signature, hmacKey, publicKey, mandatoryPointers]
	proofArray := []interface{}{
		components.Signature,
		components.HMACKey,
		components.PublicKey,
		components.MandatoryPointers,
	}

	// Create CBOR encoder in canonical mode
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return "", fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Encode the proof array
	cborData, err := enc.Marshal(proofArray)
	if err != nil {
		return "", fmt.Errorf("CBOR encoding failed: %w", err)
	}

	// Prepend CBOR tag 0xd9 0x5d 0x00 (tag 23808)
	// CBOR tag format: 0xd9 (tag 2-byte) + 2 bytes for tag number
	taggedData := make([]byte, 0, 3+len(cborData))
	taggedData = append(taggedData, 0xd9, 0x5d, 0x00) // tag 23808
	taggedData = append(taggedData, cborData...)

	// Encode as multibase base64url-no-pad (prefix 'u')
	encoded, err := multibase.Encode(multibase.Base64url, taggedData)
	if err != nil {
		return "", fmt.Errorf("multibase encoding failed: %w", err)
	}

	return encoded, nil
}

// DecodeBaseProof decodes a base proof from multibase-encoded CBOR format.
func DecodeBaseProof(encoded string) (*BaseProofComponents, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("encoded proof is empty")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("multibase decoding failed: %w", err)
	}

	// Verify CBOR tag header (0xd9 0x5d 0x00)
	if len(decoded) < 3 {
		return nil, fmt.Errorf("proof data too short")
	}
	if decoded[0] != 0xd9 || decoded[1] != 0x5d || decoded[2] != 0x00 {
		return nil, fmt.Errorf("invalid base proof header: expected 0xd9 0x5d 0x00, got 0x%02x 0x%02x 0x%02x",
			decoded[0], decoded[1], decoded[2])
	}

	// Decode CBOR payload (skip tag bytes)
	cborData := decoded[3:]
	var proofArray []interface{}
	if err := cbor.Unmarshal(cborData, &proofArray); err != nil {
		return nil, fmt.Errorf("CBOR decoding failed: %w", err)
	}

	// Verify array length
	if len(proofArray) != 4 {
		return nil, fmt.Errorf("invalid proof array length: expected 4, got %d", len(proofArray))
	}

	// Extract components
	components := &BaseProofComponents{}

	// Signature (byte array)
	if sig, ok := proofArray[0].([]byte); ok {
		components.Signature = sig
	} else {
		return nil, fmt.Errorf("invalid signature type")
	}

	// HMAC key (byte array)
	if hmac, ok := proofArray[1].([]byte); ok {
		components.HMACKey = hmac
	} else {
		return nil, fmt.Errorf("invalid HMAC key type")
	}

	// Public key (byte array)
	if pubKey, ok := proofArray[2].([]byte); ok {
		components.PublicKey = pubKey
	} else {
		return nil, fmt.Errorf("invalid public key type")
	}

	// Mandatory pointers (string array or nil)
	if proofArray[3] == nil {
		// nil/empty mandatory pointers
		components.MandatoryPointers = []string{}
	} else if ptrs, ok := proofArray[3].([]interface{}); ok {
		components.MandatoryPointers = make([]string, len(ptrs))
		for i, p := range ptrs {
			if str, ok := p.(string); ok {
				components.MandatoryPointers[i] = str
			} else {
				return nil, fmt.Errorf("invalid mandatory pointer type at index %d", i)
			}
		}
	} else {
		return nil, fmt.Errorf("invalid mandatory pointers type: got %T", proofArray[3])
	}

	return components, nil
}

// EncodeDerivedProof encodes derived proof components into CBOR format with multibase encoding.
// Returns a string like "u..." (multibase base64url-no-pad encoding).
//
// Format: multibase(cbor-tag(23809, [signature, compressedLabelMap, mandatoryIndexes, selectiveIndexes, presentationHeader]))
func EncodeDerivedProof(components *DerivedProofComponents) (string, error) {
	if components == nil {
		return "", fmt.Errorf("components is nil")
	}

	// Create CBOR array
	proofArray := []interface{}{
		components.Signature,
		components.CompressedLabelMap,
		components.MandatoryIndexes,
		components.SelectiveIndexes,
		components.PresentationHeader,
	}

	// Create CBOR encoder in canonical mode
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return "", fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Encode the proof array
	cborData, err := enc.Marshal(proofArray)
	if err != nil {
		return "", fmt.Errorf("CBOR encoding failed: %w", err)
	}

	// Prepend CBOR tag 0xd9 0x5d 0x01 (tag 23809)
	taggedData := make([]byte, 0, 3+len(cborData))
	taggedData = append(taggedData, 0xd9, 0x5d, 0x01) // tag 23809
	taggedData = append(taggedData, cborData...)

	// Encode as multibase base64url-no-pad (prefix 'u')
	encoded, err := multibase.Encode(multibase.Base64url, taggedData)
	if err != nil {
		return "", fmt.Errorf("multibase encoding failed: %w", err)
	}

	return encoded, nil
}

// DecodeDerivedProof decodes a derived proof from multibase-encoded CBOR format.
func DecodeDerivedProof(encoded string) (*DerivedProofComponents, error) {
	if len(encoded) == 0 {
		return nil, fmt.Errorf("encoded proof is empty")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("multibase decoding failed: %w", err)
	}

	// Verify CBOR tag header (0xd9 0x5d 0x01)
	if len(decoded) < 3 {
		return nil, fmt.Errorf("proof data too short")
	}
	if decoded[0] != 0xd9 || decoded[1] != 0x5d || decoded[2] != 0x01 {
		return nil, fmt.Errorf("invalid derived proof header: expected 0xd9 0x5d 0x01, got 0x%02x 0x%02x 0x%02x",
			decoded[0], decoded[1], decoded[2])
	}

	// Decode CBOR payload (skip tag bytes)
	cborData := decoded[3:]
	var proofArray []interface{}
	if err := cbor.Unmarshal(cborData, &proofArray); err != nil {
		return nil, fmt.Errorf("CBOR decoding failed: %w", err)
	}

	// Verify array length
	if len(proofArray) != 5 {
		return nil, fmt.Errorf("invalid proof array length: expected 5, got %d", len(proofArray))
	}

	components := &DerivedProofComponents{}

	// Signature (byte array)
	if sig, ok := proofArray[0].([]byte); ok {
		components.Signature = sig
	} else {
		return nil, fmt.Errorf("invalid signature type")
	}

	// Compressed label map (byte array)
	if labelMap, ok := proofArray[1].([]byte); ok {
		components.CompressedLabelMap = labelMap
	} else {
		return nil, fmt.Errorf("invalid compressed label map type")
	}

	// Mandatory indexes (int array or nil)
	if proofArray[2] == nil {
		components.MandatoryIndexes = []int{}
	} else if idxs, ok := proofArray[2].([]interface{}); ok {
		components.MandatoryIndexes = make([]int, len(idxs))
		for i, idx := range idxs {
			if intVal, ok := idx.(uint64); ok {
				components.MandatoryIndexes[i] = int(intVal)
			} else if intVal, ok := idx.(int64); ok {
				components.MandatoryIndexes[i] = int(intVal)
			} else {
				return nil, fmt.Errorf("invalid mandatory index type at index %d: %T", i, idx)
			}
		}
	} else {
		return nil, fmt.Errorf("invalid mandatory indexes type: got %T", proofArray[2])
	}

	// Selective indexes (int array or nil)
	if proofArray[3] == nil {
		components.SelectiveIndexes = []int{}
	} else if idxs, ok := proofArray[3].([]interface{}); ok {
		components.SelectiveIndexes = make([]int, len(idxs))
		for i, idx := range idxs {
			if intVal, ok := idx.(uint64); ok {
				components.SelectiveIndexes[i] = int(intVal)
			} else if intVal, ok := idx.(int64); ok {
				components.SelectiveIndexes[i] = int(intVal)
			} else {
				return nil, fmt.Errorf("invalid selective index type at index %d: %T", i, idx)
			}
		}
	} else {
		return nil, fmt.Errorf("invalid selective indexes type: got %T", proofArray[3])
	}

	// Presentation header (byte array, optional)
	if header, ok := proofArray[4].([]byte); ok {
		components.PresentationHeader = header
	} // nil is acceptable for presentation header

	return components, nil
}

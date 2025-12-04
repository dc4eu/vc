package ecdsa

import "github.com/fxamacker/cbor/v2"

// BaseProofValue represents the decoded proof value for a base proof
// Encoded as a CBOR array
type BaseProofValue struct {
	BaseSignature     []byte   `cbor:"0,keyasint"`
	PublicKey         []byte   `cbor:"1,keyasint"`
	HmacKey           []byte   `cbor:"2,keyasint"`
	Signatures        [][]byte `cbor:"3,keyasint"`
	MandatoryPointers []string `cbor:"4,keyasint"`
}

// DerivedProofValue represents the decoded proof value for a derived proof
// Encoded as a CBOR array
type DerivedProofValue struct {
	BaseSignature    []byte            `cbor:"0,keyasint"`
	PublicKey        []byte            `cbor:"1,keyasint"`
	Signatures       [][]byte          `cbor:"2,keyasint"`
	LabelMap         map[string]string `cbor:"3,keyasint"`
	MandatoryIndexes []int             `cbor:"4,keyasint"`
}

// Helper to encode as CBOR array
func toCborArray(v any) ([]byte, error) {
	// We can use the "toarray" tag if we define a struct, or just marshal a slice
	// But the struct fields have different types.
	// Let's use a struct with `cbor:",toarray"` tag.
	return cbor.Marshal(v)
}

// BaseProofValueArray is used for CBOR serialization as an array
type BaseProofValueArray struct {
	_                 struct{} `cbor:",toarray"`
	BaseSignature     []byte
	PublicKey         []byte
	HmacKey           []byte
	Signatures        [][]byte
	MandatoryPointers []string
}

// DerivedProofValueArray is used for CBOR serialization as an array
type DerivedProofValueArray struct {
	_                struct{} `cbor:",toarray"`
	BaseSignature    []byte
	PublicKey        []byte
	Signatures       [][]byte
	LabelMap         map[string]string
	MandatoryIndexes []int
}

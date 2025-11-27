//go:build vc20

package keys


import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/multiformats/go-multibase"
)

// Multikey format constants per W3C specifications
// See: https://www.w3.org/TR/vc-data-integrity/#multikey
const (
	// ECDSA P-256 public key multicodec prefix
	MulticodecP256PubKey = 0x1200
	// ECDSA P-384 public key multicodec prefix
	MulticodecP384PubKey = 0x1201
	// ECDSA secp256k1 public key multicodec prefix
	MulticodecSecp256k1PubKey = 0xe7
)

// ECDSAPublicKeyToMultikey encodes an ECDSA public key to Multikey format.
// Returns a string like "z..." (multibase base58-btc encoding).
//
// Format: multibase(multicodec || public-key-bytes)
// - P-256: multicodec 0x1200 + uncompressed key (0x04 + X + Y)
// - P-384: multicodec 0x1201 + uncompressed key (0x04 + X + Y)
func ECDSAPublicKeyToMultikey(pubKey *ecdsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", fmt.Errorf("public key is nil")
	}

	var multicodec uint16
	var expectedSize int

	switch pubKey.Curve.Params().Name {
	case "P-256":
		multicodec = MulticodecP256PubKey
		expectedSize = 32 // 256 bits / 8
	case "P-384":
		multicodec = MulticodecP384PubKey
		expectedSize = 48 // 384 bits / 8
	default:
		return "", fmt.Errorf("unsupported curve: %s", pubKey.Curve.Params().Name)
	}

	// Encode the public key in uncompressed format (0x04 + X + Y)
	xBytes := pubKey.X.Bytes()
	yBytes := pubKey.Y.Bytes()

	// Pad to expected size if needed (leading zeros may be dropped)
	xPadded := make([]byte, expectedSize)
	yPadded := make([]byte, expectedSize)
	copy(xPadded[expectedSize-len(xBytes):], xBytes)
	copy(yPadded[expectedSize-len(yBytes):], yBytes)

	// Create multikey bytes: multicodec (varint) + 0x04 + X + Y
	multicodecBytes := encodeVarint(uint64(multicodec))
	multikeyBytes := make([]byte, 0, len(multicodecBytes)+1+len(xPadded)+len(yPadded))
	multikeyBytes = append(multikeyBytes, multicodecBytes...)
	multikeyBytes = append(multikeyBytes, 0x04) // uncompressed point indicator
	multikeyBytes = append(multikeyBytes, xPadded...)
	multikeyBytes = append(multikeyBytes, yPadded...)

	// Encode as multibase base58-btc (prefix 'z')
	encoded, err := multibase.Encode(multibase.Base58BTC, multikeyBytes)
	if err != nil {
		return "", fmt.Errorf("multibase encoding failed: %w", err)
	}

	return encoded, nil
}

// MultikeyToECDSAPublicKey decodes a Multikey string to an ECDSA public key.
// Supports P-256 and P-384 curves.
func MultikeyToECDSAPublicKey(multikey string) (*ecdsa.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("multikey is empty")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("multibase decoding failed: %w", err)
	}

	if len(decoded) < 3 {
		return nil, fmt.Errorf("multikey too short")
	}

	// Decode multicodec (varint)
	multicodec, bytesRead := binary.Uvarint(decoded)
	if bytesRead <= 0 {
		return nil, fmt.Errorf("invalid multicodec varint")
	}

	keyBytes := decoded[bytesRead:]
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("no key bytes after multicodec")
	}

	// Check for uncompressed point format (0x04)
	if keyBytes[0] != 0x04 {
		return nil, fmt.Errorf("only uncompressed ECDSA keys are supported (expected 0x04 prefix)")
	}

	keyBytes = keyBytes[1:] // skip 0x04

	var curve elliptic.Curve
	var expectedSize int

	switch multicodec {
	case MulticodecP256PubKey:
		curve = elliptic.P256()
		expectedSize = 32
	case MulticodecP384PubKey:
		curve = elliptic.P384()
		expectedSize = 48
	default:
		return nil, fmt.Errorf("unsupported multicodec: 0x%x", multicodec)
	}

	// X and Y coordinates should each be expectedSize bytes
	if len(keyBytes) != expectedSize*2 {
		return nil, fmt.Errorf("invalid key length for curve: got %d, expected %d", len(keyBytes), expectedSize*2)
	}

	x := new(big.Int).SetBytes(keyBytes[:expectedSize])
	y := new(big.Int).SetBytes(keyBytes[expectedSize:])

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("public key point is not on the curve")
	}

	return pubKey, nil
}

// encodeVarint encodes an unsigned integer as a variable-length integer (varint).
// This is used for multicodec encoding.
func encodeVarint(n uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	bytesWritten := binary.PutUvarint(buf, n)
	return buf[:bytesWritten]
}

// GetCurveName returns the curve name for verification method type determination
func GetCurveName(pubKey *ecdsa.PublicKey) (string, error) {
	if pubKey == nil {
		return "", fmt.Errorf("public key is nil")
	}
	return pubKey.Curve.Params().Name, nil
}

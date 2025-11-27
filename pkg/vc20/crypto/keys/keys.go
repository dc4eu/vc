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
	// ECDSA P-256 private key multicodec prefix
	MulticodecP256PrivKey = 0x1306
	// ECDSA P-384 private key multicodec prefix
	MulticodecP384PrivKey = 0x1307
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

	// Check key format (compressed or uncompressed)
	prefix := keyBytes[0]
	keyBytes = keyBytes[1:]

	var x, y *big.Int

	if prefix == 0x04 {
		// Uncompressed format: 0x04 + X + Y
		if len(keyBytes) != expectedSize*2 {
			return nil, fmt.Errorf("invalid uncompressed key length for curve: got %d, expected %d", len(keyBytes), expectedSize*2)
		}

		x = new(big.Int).SetBytes(keyBytes[:expectedSize])
		y = new(big.Int).SetBytes(keyBytes[expectedSize:])
	} else if prefix == 0x02 || prefix == 0x03 {
		// Compressed format: 0x02/0x03 + X
		if len(keyBytes) != expectedSize {
			return nil, fmt.Errorf("invalid compressed key length for curve: got %d, expected %d", len(keyBytes), expectedSize)
		}

		x = new(big.Int).SetBytes(keyBytes)

		// Decompress the Y coordinate
		// y² = x³ - 3x + b (for P-256 and P-384)
		params := curve.Params()
		
		// Calculate x³ - 3x + b
		x3 := new(big.Int).Mul(x, x)      // x²
		x3.Mul(x3, x)                       // x³
		
		threeX := new(big.Int).Mul(x, big.NewInt(3))
		x3.Sub(x3, threeX)                  // x³ - 3x
		x3.Add(x3, params.B)                // x³ - 3x + b
		x3.Mod(x3, params.P)                // mod p

		// Compute square root
		y = new(big.Int).ModSqrt(x3, params.P)
		if y == nil {
			return nil, fmt.Errorf("invalid compressed public key: point not on curve")
		}

		// Check if we need to negate y based on prefix
		// 0x02 means y is even, 0x03 means y is odd
		yIsOdd := y.Bit(0) == 1
		prefixIsOdd := prefix == 0x03

		if yIsOdd != prefixIsOdd {
			y.Sub(params.P, y)
		}
	} else {
		return nil, fmt.Errorf("unsupported key format prefix: 0x%02x (expected 0x02, 0x03, or 0x04)", prefix)
	}

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

// MultikeyToECDSAPrivateKey decodes a Multikey string to an ECDSA private key.
// Supports P-256 and P-384 curves.
//
// Format: multibase(multicodec || private-key-bytes)
// - P-256: multicodec 0x1306 + 32-byte D value
// - P-384: multicodec 0x1307 + 48-byte D value
func MultikeyToECDSAPrivateKey(multikey string) (*ecdsa.PrivateKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("multikey is empty")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("multibase decoding failed: %w", err)
	}

	if len(decoded) < 2 {
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

	var curve elliptic.Curve
	var expectedSize int

	switch multicodec {
	case MulticodecP256PrivKey:
		curve = elliptic.P256()
		expectedSize = 32
	case MulticodecP384PrivKey:
		curve = elliptic.P384()
		expectedSize = 48
	default:
		return nil, fmt.Errorf("unsupported private key multicodec: 0x%x", multicodec)
	}

	// Private key D value should be expectedSize bytes
	if len(keyBytes) != expectedSize {
		return nil, fmt.Errorf("invalid private key length for curve: got %d, expected %d", len(keyBytes), expectedSize)
	}

	d := new(big.Int).SetBytes(keyBytes)

	// Create private key and derive public key
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: d,
	}

	// Compute public key from private key
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	return privKey, nil
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

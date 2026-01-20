package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"maps"

	"github.com/golang-jwt/jwt/v5"
)

// MakeJWT creates a signed JWT with the given header, body, signing method, and key.
// The header parameter is merged with default headers set by the signing method.
func MakeJWT(header, body jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	token := jwt.NewWithClaims(signingMethod, body)

	// Merge provided header fields with defaults (provided values override defaults)
	maps.Copy(token.Header, header)

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// GetSigningMethodFromKey determines the JWT signing method from the private key type
func GetSigningMethodFromKey(privateKey any) jwt.SigningMethod {
	// Check if the key is RSA
	if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
		// Determine RSA algorithm based on key size
		keySize := rsaKey.N.BitLen()
		switch {
		case keySize >= 4096:
			return jwt.SigningMethodRS512
		case keySize >= 3072:
			return jwt.SigningMethodRS384
		default:
			return jwt.SigningMethodRS256
		}
	}

	// Check if the key is ECDSA
	if ecKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
		// Determine algorithm based on the curve of the ECDSA key
		switch ecKey.Curve.Params().Name {
		case "P-256":
			return jwt.SigningMethodES256
		case "P-384":
			return jwt.SigningMethodES384
		case "P-521":
			return jwt.SigningMethodES512
		default:
			// Default to ES256 for unknown curves
			return jwt.SigningMethodES256
		}
	}

	// Default to RS256 if key type is unknown
	return jwt.SigningMethodRS256
}

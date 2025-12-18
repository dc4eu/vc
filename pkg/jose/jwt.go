package jose

import (
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

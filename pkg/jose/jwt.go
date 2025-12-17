package jose

import (
	"github.com/golang-jwt/jwt/v5"
)

// MakeJWT creates a signed JWT with the given header, body, signing method, and key
func MakeJWT(header, body jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	token := jwt.NewWithClaims(signingMethod, body)
	token.Header = header

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

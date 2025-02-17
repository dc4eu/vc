package jose

import (
	"github.com/golang-jwt/jwt/v5"
)

// MakeJWT mocks the jwt
func MakeJWT(header, body jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	token := jwt.NewWithClaims(signingMethod, body)
	token.Header = header

	singedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return singedToken, nil
}

package sdjwtvc

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Sign signs the JWT with the provided header, body, signing method, and signing key
func Sign(header, body jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	token := jwt.NewWithClaims(signingMethod, body)
	token.Header = header

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Combine combines the token, disclosures and keyBinding into an SD-JWT format
func Combine(token string, disclosures []string, keyBinding string) string {
	if len(disclosures) > 0 {
		token = fmt.Sprintf("%s~%s~", token, strings.Join(disclosures, "~"))
	} else {
		token = fmt.Sprintf("%s~", token)
	}

	if keyBinding != "" {
		token = fmt.Sprintf("%s%s", token, keyBinding)
	}

	return token
}

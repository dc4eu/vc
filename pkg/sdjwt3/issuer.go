package sdjwt3

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// AddCNF adds a CNF claim to the body
func AddCNF(cnf map[string]any, body map[string]any) {
	body["cnf"] = cnf
}

// Sign signs the jwt
func Sign(header, body jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	token := jwt.NewWithClaims(signingMethod, body)
	token.Header = header

	singedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return singedToken, nil
}

// Combine combines the token, disclosures and keyBinding
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

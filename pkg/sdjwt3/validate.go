package sdjwt3

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Validate validates a signed sdjwt
func Validate(sdjwt string, pubkey crypto.PublicKey) (bool, error) {
	header, body, signature, selectiveDisclosures, err := SplitToken(sdjwt)
	if err != nil {
		return false, err
	}

	claims := jwt.MapClaims{}

	completeToken := fmt.Sprintf("%s.%s.%s", header, body, signature)
	token, err := jwt.ParseWithClaims(completeToken, claims, func(token *jwt.Token) (any, error) {
		return pubkey.(*ecdsa.PublicKey), nil
	})
	if err != nil {
		return false, err
	}

	if !selectiveDisclosureUniq(selectiveDisclosures) {
		return false, errors.New("duplicate selective disclosure")
	}

	return token.Valid, nil
}

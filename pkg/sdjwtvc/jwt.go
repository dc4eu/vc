package sdjwtvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Signer defines the interface for cryptographic signing operations.
type Signer interface {
	Sign(ctx context.Context, data []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
	PublicKey() any
}

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

// SignWithSigner signs the JWT using a Signer interface (for HSM support).
func SignWithSigner(ctx context.Context, header, body jwt.MapClaims, signer Signer) (string, error) {
	// Set algorithm and kid from signer
	header["alg"] = signer.Algorithm()
	header["kid"] = signer.KeyID()

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signing input
	signingInput := headerB64 + "." + payloadB64

	// Sign using the signer interface
	signature, err := signer.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Encode signature
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
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

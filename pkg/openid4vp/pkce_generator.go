package openid4vp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const pkceCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

const codeVerifierLength = 128

func GenerateCodeVerifier() (string, error) {
	b := make([]byte, codeVerifierLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fel vid generering av code_verifier: %w", err)
	}

	for i := range b {
		b[i] = pkceCharset[int(b[i])%len(pkceCharset)]
	}

	return string(b), nil
}

func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

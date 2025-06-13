package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/dchest/uniuri"
)

// GenerateCryptographicNonce generates a cryptographically secure nonce base64URL encoded, or error.
func GenerateCryptographicNonce(n int) (string, error) {
	// Assert cryptographically secure PRNG is available.
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return "", fmt.Errorf("crypto/rand is unavailable: %w", err)
	}

	// Generate a random nonce of n length.
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func GenerateCryptographicNonceWithLength(n int) string {
	return uniuri.NewLen(n)
}

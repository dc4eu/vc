package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// GenerateCryptographicNonce generates a cryptographically secure nonce base64URL encoded, or error.
func GenerateCryptographicNonce(n int) (string, error) {
	// Assert cryptographically secure PRNG is available.
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}

	// Generate a random nonce of n length.
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

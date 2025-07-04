package oauth2

import (
	"crypto/rand"
)

// GenerateCryptographicNonceFixedLength generates a cryptographically secure nonce of a fixed length.
func GenerateCryptographicNonceFixedLength(length int) string {
	s := rand.Text() + rand.Text()
	if length > 52 || length <= 0 {
		return s
	}

	return s[:length]

}

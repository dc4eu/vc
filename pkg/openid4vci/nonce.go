package openid4vci

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// NonceResponse https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-response
type NonceResponse struct {
	CNonce string `json:"c_nonce"`
}

// GenerateNonce generates a random nonce, if size is 0, it will default to 32 bytes. Maximum byte size is 94 witch will result in 128 long nonce.
func GenerateNonce(size int) (string, error) {
	if size == 0 {
		size = 32
	}
	if size >= 94 {
		size = 94
	}
	nonceBytes := make([]byte, size)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

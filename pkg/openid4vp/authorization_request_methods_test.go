package openid4vp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func mockRSAPrivateKey(t *testing.T) crypto.PrivateKey {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	return privKey
}

func TestAuthorizationRequestSign(t *testing.T) {
	tts := []struct {
		name          string
		authorization RequestObject
		signingMethod jwt.SigningMethod
		signingKey    any
		x5c           []string
	}{
		{
			name:          "valid RS256",
			authorization: RequestObject{},
			signingMethod: jwt.GetSigningMethod("RS256"),
			signingKey:    mockRSAPrivateKey(t),
			x5c:           []string{"test"},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := tt.authorization.Sign(tt.signingMethod, tt.signingKey, tt.x5c)
			assert.NoError(t, err)

			fmt.Println("Signed JWT:", signed)
		})
	}
}

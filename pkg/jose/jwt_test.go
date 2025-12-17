package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeJWT(t *testing.T) {
	t.Run("creates signed JWT with EC key", func(t *testing.T) {
		keyPath := createTestECKey(t)

		jwk, privateKey, err := CreateJWK(keyPath)
		require.NoError(t, err)

		ecKey := privateKey.(*ecdsa.PrivateKey)

		header := jwt.MapClaims{
			"alg": "ES256",
			"typ": "openid4vci-proof+jwt",
			"kid": "key-1",
		}
		body := jwt.MapClaims{
			"iss":   "joe",
			"aud":   "https://example.com",
			"iat":   1300819380,
			"nonce": "n-0S6_WzA2Mj",
			"jwk":   jwk,
		}

		signedToken, err := MakeJWT(header, body, jwt.SigningMethodES256, ecKey)
		require.NoError(t, err)
		assert.NotEmpty(t, signedToken)

		// Verify the token can be parsed
		token, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
			return &ecKey.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("creates signed JWT with RSA key", func(t *testing.T) {
		keyPath := createTestRSAKey(t)

		jwk, privateKey, err := CreateJWK(keyPath)
		require.NoError(t, err)

		rsaKey := privateKey.(*rsa.PrivateKey)

		header := jwt.MapClaims{
			"alg": "RS256",
			"typ": "JWT",
			"kid": "rsa-key-1",
		}
		body := jwt.MapClaims{
			"iss":   "joe",
			"aud":   "https://example.com",
			"iat":   1300819380,
			"nonce": "n-0S6_WzA2Mj",
			"jwk":   jwk,
		}

		signedToken, err := MakeJWT(header, body, jwt.SigningMethodRS256, rsaKey)
		require.NoError(t, err)
		assert.NotEmpty(t, signedToken)

		// Verify the token can be parsed
		token, err := jwt.Parse(signedToken, func(token *jwt.Token) (interface{}, error) {
			return &rsaKey.PublicKey, nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)
	})

	t.Run("returns error for nil key", func(t *testing.T) {
		header := jwt.MapClaims{"alg": "ES256"}
		body := jwt.MapClaims{"iss": "test"}

		_, err := MakeJWT(header, body, jwt.SigningMethodES256, nil)
		assert.Error(t, err)
	})

	t.Run("returns error for wrong key type", func(t *testing.T) {
		header := jwt.MapClaims{"alg": "ES256"}
		body := jwt.MapClaims{"iss": "test"}

		// Use a string instead of a key
		_, err := MakeJWT(header, body, jwt.SigningMethodES256, "not-a-key")
		assert.Error(t, err)
	})
}

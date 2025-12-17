package jose

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSigningKey(t *testing.T) {
	t.Run("parses EC key SEC1 format", func(t *testing.T) {
		keyPath := createTestECKey(t)
		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*ecdsa.PrivateKey)
		assert.True(t, ok, "expected *ecdsa.PrivateKey")
	})

	t.Run("parses EC key PKCS8 format", func(t *testing.T) {
		keyPath := createTestECKeyPKCS8(t)
		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*ecdsa.PrivateKey)
		assert.True(t, ok, "expected *ecdsa.PrivateKey")
	})

	t.Run("parses RSA key PKCS1 format (RSA PRIVATE KEY)", func(t *testing.T) {
		keyPath := createTestRSAKey(t)

		// Verify the key file has the expected PEM block type
		keyBytes, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		block, _ := pem.Decode(keyBytes)
		require.NotNil(t, block)
		assert.Equal(t, "RSA PRIVATE KEY", block.Type, "expected PKCS1 format with RSA PRIVATE KEY block type")

		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*rsa.PrivateKey)
		assert.True(t, ok, "expected *rsa.PrivateKey")
	})

	t.Run("parses RSA key PKCS8 format (PRIVATE KEY)", func(t *testing.T) {
		keyPath := createTestRSAKeyPKCS8(t)

		// Verify the key file has the expected PEM block type
		keyBytes, err := os.ReadFile(keyPath)
		require.NoError(t, err)
		block, _ := pem.Decode(keyBytes)
		require.NotNil(t, block)
		assert.Equal(t, "PRIVATE KEY", block.Type, "expected PKCS8 format with PRIVATE KEY block type")

		key, err := ParseSigningKey(keyPath)
		require.NoError(t, err)
		assert.NotNil(t, key)
		_, ok := key.(*rsa.PrivateKey)
		assert.True(t, ok, "expected *rsa.PrivateKey")
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		_, err := ParseSigningKey("/non/existent/path.pem")
		assert.Error(t, err)
	})

	t.Run("returns error for invalid key", func(t *testing.T) {
		keyPath := createInvalidKeyFile(t)
		_, err := ParseSigningKey(keyPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type")
	})
}

func TestCreateJWK(t *testing.T) {
	t.Run("creates JWK from EC key", func(t *testing.T) {
		keyPath := createTestECKey(t)

		jwk, privateKey, err := CreateJWK(keyPath)
		require.NoError(t, err)

		assert.Equal(t, "EC", jwk.KTY)
		assert.Equal(t, "P-256", jwk.CRV)
		assert.NotEmpty(t, jwk.X)
		assert.NotEmpty(t, jwk.Y)
		assert.Empty(t, jwk.N)
		assert.Empty(t, jwk.E)
		assert.NotNil(t, privateKey)
	})

	t.Run("creates JWK from RSA key", func(t *testing.T) {
		keyPath := createTestRSAKey(t)

		jwk, privateKey, err := CreateJWK(keyPath)
		require.NoError(t, err)

		assert.Equal(t, "RSA", jwk.KTY)
		assert.Empty(t, jwk.CRV)
		assert.Empty(t, jwk.X)
		assert.Empty(t, jwk.Y)
		assert.NotEmpty(t, jwk.N)
		assert.NotEmpty(t, jwk.E)
		assert.NotNil(t, privateKey)
	})

	t.Run("returns error for non-existent file", func(t *testing.T) {
		_, _, err := CreateJWK("/non/existent/path.pem")
		assert.Error(t, err)
	})

	t.Run("returns error for invalid key", func(t *testing.T) {
		keyPath := createInvalidKeyFile(t)
		_, _, err := CreateJWK(keyPath)
		assert.Error(t, err)
	})
}

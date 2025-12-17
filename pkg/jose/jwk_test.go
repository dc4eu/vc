package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestECKey(t *testing.T) string {
	t.Helper()

	// Generate ECDSA P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode to PEM (SEC 1 / traditional format)
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ec_key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600))

	return keyPath
}

func createTestECKeyPKCS8(t *testing.T) string {
	t.Helper()

	// Generate ECDSA P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode to PKCS8 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_ec_key_pkcs8.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600))

	return keyPath
}

func createTestRSAKey(t *testing.T) string {
	t.Helper()

	// Generate RSA 2048 key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode to PEM (PKCS1 format)
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_rsa_key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600))

	return keyPath
}

func createTestRSAKeyPKCS8(t *testing.T) string {
	t.Helper()

	// Generate RSA 2048 key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Encode to PKCS8 format
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Write to temp file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_rsa_key_pkcs8.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600))

	return keyPath
}

func createInvalidKeyFile(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid_key.pem")
	require.NoError(t, os.WriteFile(keyPath, []byte("not a valid key"), 0600))

	return keyPath
}

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

package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWK is a JSON Web Key
type JWK struct {
	KTY string `json:"kty"`
	CRV string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// ParseSigningKey parses a private key from a PEM file (supports EC and RSA in various formats)
func ParseSigningKey(signingKeyPath string) (crypto.PrivateKey, error) {
	keyByte, err := os.ReadFile(filepath.Clean(signingKeyPath))
	if err != nil {
		return nil, err
	}
	if keyByte == nil {
		return nil, errors.New("private key missing")
	}

	// Try EC first (SEC1 and PKCS8 formats)
	if privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyByte); err == nil {
		return privateKey, nil
	}

	// Try RSA (PKCS1 and PKCS8 formats)
	if privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyByte); err == nil {
		return privateKey, nil
	}

	// Try PKCS8 generic (handles both EC and RSA in PKCS8 format)
	block, _ := pem.Decode(keyByte)
	if block != nil && block.Type == "PRIVATE KEY" {
		if privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return privateKey, nil
		}
	}

	// Try PKCS1 RSA explicitly
	if block != nil && block.Type == "RSA PRIVATE KEY" {
		if privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return privateKey, nil
		}
	}

	return nil, errors.New("unsupported key type: expected EC or RSA private key in PEM format (SEC1, PKCS1, or PKCS8)")
}

// ParseECSigningKey parses an EC private key from a PEM file
func ParseECSigningKey(signingKeyPath string) (*ecdsa.PrivateKey, error) {
	keyByte, err := os.ReadFile(filepath.Clean(signingKeyPath))
	if err != nil {
		return nil, err
	}
	if keyByte == nil {
		return nil, errors.New("private key missing")
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyByte)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// ParseRSASigningKey parses an RSA private key from a PEM file
func ParseRSASigningKey(signingKeyPath string) (*rsa.PrivateKey, error) {
	keyByte, err := os.ReadFile(filepath.Clean(signingKeyPath))
	if err != nil {
		return nil, err
	}
	if keyByte == nil {
		return nil, errors.New("private key missing")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyByte)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// CreateJWK creates a JWK from the signing key
func CreateJWK(signingKeyPath string) (*JWK, *ecdsa.PrivateKey, error) {
	privateKey, err := ParseECSigningKey(signingKeyPath)
	if err != nil {
		return nil, nil, err
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Marshal to JSON and unmarshal to our JWK struct
	jwkJSON, err := json.Marshal(key)
	if err != nil {
		return nil, nil, err
	}

	result := &JWK{}
	if err := json.Unmarshal(jwkJSON, result); err != nil {
		return nil, nil, err
	}

	return result, privateKey, nil
}

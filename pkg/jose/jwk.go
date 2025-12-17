package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWK is a JSON Web Key supporting EC and RSA key types
type JWK struct {
	KTY string `json:"kty"`
	// EC key fields
	CRV string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// RSA key fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// ParseSigningKey parses a private key from a PEM file (supports EC and RSA in various formats)
// Handles SEC1, PKCS1, and PKCS8 formats automatically.
func ParseSigningKey(signingKeyPath string) (crypto.PrivateKey, error) {
	keyByte, err := os.ReadFile(filepath.Clean(signingKeyPath))
	if err != nil {
		return nil, err
	}
	if keyByte == nil {
		return nil, errors.New("private key missing")
	}

	// Try EC (handles SEC1 and PKCS8 formats)
	if privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyByte); err == nil {
		return privateKey, nil
	}

	// Try RSA (handles PKCS1 and PKCS8 formats)
	if privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyByte); err == nil {
		return privateKey, nil
	}

	return nil, errors.New("unsupported key type: expected EC or RSA private key in PEM format")
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

// CreateJWK creates a JWK from a signing key file (supports EC and RSA)
func CreateJWK(signingKeyPath string) (*JWK, crypto.PrivateKey, error) {
	privateKey, err := ParseSigningKey(signingKeyPath)
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

// CreateECJWK creates a JWK from an EC signing key file
func CreateECJWK(signingKeyPath string) (*JWK, *ecdsa.PrivateKey, error) {
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

// CreateRSAJWK creates a JWK from an RSA signing key file
func CreateRSAJWK(signingKeyPath string) (*JWK, *rsa.PrivateKey, error) {
	privateKey, err := ParseRSASigningKey(signingKeyPath)
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

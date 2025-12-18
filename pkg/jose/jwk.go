package jose

import (
	"crypto"
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

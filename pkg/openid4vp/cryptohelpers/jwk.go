package cryptohelpers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWK represents a JSON Web Key
type JWK struct {
	X5C []string `json:"x5c,omitempty"`

	Kty string `json:"kty"`           // Key Type, e.g., "EC", "RSA", "OKP"
	Use string `json:"use,omitempty"` // Public Key Use, e.g., "sig", "enc"
	Kid string `json:"kid,omitempty"` // Key ID

	// EC fields
	Crv string `json:"crv,omitempty"` // Curve, e.g., "P-256"
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// RSA fields
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// Symmetric keys
	K string `json:"k,omitempty"` // Symmetric key value (e.g., for "oct")

	// Common optional fields
	Alg string `json:"alg,omitempty"` // Algorithm (optional, but common)
}

type JWSHeader struct {
	Alg string          `json:"alg"`
	Cnf json.RawMessage `json:"cnf"` // `cnf` can contain both `jwk` or `jwks`
}

type CNF struct {
	JWK  json.RawMessage `json:"jwk,omitempty"`
	JWKS json.RawMessage `json:"jwks,omitempty"`
}

// parseJWKFromHeader extracts a public key from JWS header (handling both `jwk` and `jwks`)
func ParseJWKFromHeader(headerData []byte) (interface{}, error) {
	var header JWSHeader
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWS header: %v", err)
	}

	if len(header.Cnf) == 0 {
		return nil, errors.New("missing 'cnf' in JWS header")
	}

	var cnf CNF
	if err := json.Unmarshal(header.Cnf, &cnf); err != nil {
		return nil, fmt.Errorf("failed to parse cnf: %v", err)
	}

	if len(cnf.JWK) > 0 {
		return parseJWK(cnf.JWK)
	} else if len(cnf.JWKS) > 0 {
		return parseJWKS(cnf.JWKS)
	}

	return nil, errors.New("neither 'jwk' nor 'jwks' found in 'cnf'")
}

// parseJWKS extracts the first key from a JWKS (JWK Set)
func parseJWKS(jwksData []byte) (interface{}, error) {
	var jwks struct {
		Keys []json.RawMessage `json:"keys"`
	}

	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %v", err)
	}

	if len(jwks.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}

	// extract first key
	return parseJWK(jwks.Keys[0])
}

// parseJWK converts a JWK (JSON Web Key) into a usable public key.
func parseJWK(jwkData []byte) (interface{}, error) {
	var jwk JWK
	if err := json.Unmarshal(jwkData, &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %v", err)
	}

	// Handle x5c (X.509 certificate chain) if present
	if len(jwk.X5C) > 0 {
		certPEM, err := parseX5C(jwk.X5C)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c: %v", err)
		}
		return certPEM, nil
	}

	switch jwk.Kty {
	case "RSA":
		return parseRSAPublicKey(jwk)
	case "EC":
		return parseECDSAPublicKey(jwk)
	case "OKP": // Ed25519
		return parseEd25519PublicKey(jwk)
	default:
		return nil, fmt.Errorf("unknown JWK key type: %s", jwk.Kty)
	}
}

// parseRSAPublicKey extracts an RSA public key from a JWK.
func parseRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, errors.New("RSA JWK is missing 'n' (modulus) and/or 'e' (exponent)")
	}

	// Decode base64 values
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %v", err)
	}

	// Convert exponent from bytes to integer
	var eInt int
	if len(eBytes) == 1 {
		eInt = int(eBytes[0])
	} else if len(eBytes) <= 4 {
		eInt = int(binary.BigEndian.Uint32(append(make([]byte, 4-len(eBytes)), eBytes...)))
	} else {
		return nil, errors.New("RSA exponent is too large")
	}

	// Create RSA public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	return pubKey, nil
}

// parseECDSAPublicKey extracts an ECDSA public key from a JWK.
func parseECDSAPublicKey(jwk JWK) (*ecdsa.PublicKey, error) {
	if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
		return nil, errors.New("EC JWK is missing 'crv' (curve), 'x' and/or 'y' (coordinates)")
	}

	// Decode base64 values
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %v", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %v", err)
	}

	// Determine curve
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %s", jwk.Crv)
	}

	// Create ECDSA public key
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return pubKey, nil
}

// parseEd25519PublicKey extracts an Ed25519 public key from a JWK.
func parseEd25519PublicKey(jwk JWK) (ed25519.PublicKey, error) {
	if jwk.X == "" {
		return nil, errors.New("Ed25519 JWK is missing 'x' (public key)")
	}

	// Decode base64 value
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 public key: %v", err)
	}

	// Validate key length
	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: expected %d bytes, got %d", ed25519.PublicKeySize, len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

// parseX5C extracts the public key from an X.509 certificate in JWK's x5c field.
func parseX5C(x5c []string) (interface{}, error) {
	if len(x5c) == 0 {
		return nil, errors.New("empty x5c certificate chain")
	}

	// x5c is a base64-encoded certificate chain, extract the first certificate
	certDER, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode x5c certificate: %v", err)
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x5c certificate: %v", err)
	}

	// Return the public key from the certificate
	return cert.PublicKey, nil
}

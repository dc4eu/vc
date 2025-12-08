package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// SoftwareSigner implements Signer using in-memory software keys.
type SoftwareSigner struct {
	privateKey crypto.Signer
	publicKey  any
	algorithm  string
	keyID      string
}

// NewSoftwareSigner creates a new SoftwareSigner from a private key.
// Supports *rsa.PrivateKey and *ecdsa.PrivateKey.
func NewSoftwareSigner(privateKey any, keyID string) (*SoftwareSigner, error) {
	s := &SoftwareSigner{
		keyID: keyID,
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		s.privateKey = key
		s.publicKey = &key.PublicKey
		s.algorithm = rsaAlgorithm(key)
	case *ecdsa.PrivateKey:
		s.privateKey = key
		s.publicKey = &key.PublicKey
		s.algorithm = ecdsaAlgorithm(key)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}

	return s, nil
}

// Sign signs the data using the software key.
func (s *SoftwareSigner) Sign(ctx context.Context, data []byte) ([]byte, error) {
	switch key := s.privateKey.(type) {
	case *rsa.PrivateKey:
		return s.signRSA(key, data)
	case *ecdsa.PrivateKey:
		return s.signECDSA(key, data)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", s.privateKey)
	}
}

// Algorithm returns the JWT algorithm name.
func (s *SoftwareSigner) Algorithm() string {
	return s.algorithm
}

// KeyID returns the key identifier.
func (s *SoftwareSigner) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key.
func (s *SoftwareSigner) PublicKey() any {
	return s.publicKey
}

// signRSA signs data with RSA using PKCS#1 v1.5.
func (s *SoftwareSigner) signRSA(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	hash := rsaHash(s.algorithm)
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	return rsa.SignPKCS1v15(rand.Reader, key, hash, hashed)
}

// signECDSA signs data with ECDSA.
func (s *SoftwareSigner) signECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := ecdsaHash(s.algorithm)
	h := hash.New()
	h.Write(data)
	hashed := h.Sum(nil)

	r, ss, err := ecdsa.Sign(rand.Reader, key, hashed)
	if err != nil {
		return nil, err
	}

	// Convert to fixed-size format for JWT
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*keyBytes)

	rBytes := r.Bytes()
	sBytes := ss.Bytes()

	copy(sig[keyBytes-len(rBytes):keyBytes], rBytes)
	copy(sig[2*keyBytes-len(sBytes):], sBytes)

	return sig, nil
}

// rsaAlgorithm determines the RSA algorithm based on key size.
func rsaAlgorithm(key *rsa.PrivateKey) string {
	keySize := key.N.BitLen()
	switch {
	case keySize >= 4096:
		return "RS512"
	case keySize >= 3072:
		return "RS384"
	default:
		return "RS256"
	}
}

// ecdsaAlgorithm determines the ECDSA algorithm based on curve.
func ecdsaAlgorithm(key *ecdsa.PrivateKey) string {
	switch key.Curve.Params().BitSize {
	case 384:
		return "ES384"
	case 521:
		return "ES512"
	default:
		return "ES256"
	}
}

// rsaHash returns the hash function for the given RSA algorithm.
func rsaHash(alg string) crypto.Hash {
	switch alg {
	case "RS384":
		return crypto.SHA384
	case "RS512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// ecdsaHash returns the hash function for the given ECDSA algorithm.
func ecdsaHash(alg string) crypto.Hash {
	switch alg {
	case "ES384":
		return crypto.SHA384
	case "ES512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

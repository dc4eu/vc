package apiv1

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strings"
	"vc/internal/verifier/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
)

// Client holds the public api object
type Client struct {
	cfg              *model.Cfg
	db               *db.Service
	log              *logger.Log
	verifierKeyPair  *openid4vp.KeyPair
	verifierX509Cert *openid4vp.CertData

	//TODO: remove after mongodb is being used
	currentSequence int64
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg: cfg,
		db:  db,
		log: log.New("apiv1"),
	}

	//TODO: Change filename/config value for private key file path
	keyPair, err := LoadKeyPairFromPEMFile("/private_verifier_rsa.pem")
	if err != nil {
		c.log.Error(err, "Failed to load verifier key pair")
		return nil, err
	}
	c.verifierKeyPair = keyPair

	cert, err := loadCertFromPEMFile("/verifier_x509_cert.pem")
	if err != nil {
		c.log.Error(err, "Failed to load x509 certificate")
		return nil, err
	}
	c.verifierX509Cert = cert

	c.log.Info("Started")

	return c, nil
}

func LoadKeyPairFromPEMFile(filepath string) (*openid4vp.KeyPair, error) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("unable to read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, errors.New("no valid private key found in PEM")
	}

	var privKey crypto.PrivateKey

	// === Try PKCS#8 ===
	privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return buildKeyPair(privKey)
	}

	// === Try RSA PKCS#1 ===
	if rsaKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
		return buildKeyPair(rsaKey)
	}

	// === Try EC SEC1 ===
	if ecKey, err3 := x509.ParseECPrivateKey(block.Bytes); err3 == nil {
		return buildKeyPair(ecKey)
	}

	// === Try raw Ed25519 ===
	if edKey, ok := parseRawEd25519(block.Bytes); ok {
		return buildKeyPair(edKey)
	}

	return nil, errors.New("unsupported or unknown private key format: tried PKCS#8, PKCS#1 (RSA), SEC1 (EC), raw Ed25519")
}

func buildKeyPair(privKey crypto.PrivateKey) (*openid4vp.KeyPair, error) {
	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		return &openid4vp.KeyPair{
			PrivateKey:         key,
			PublicKey:          &key.PublicKey,
			SigningMethodToUse: jwt.SigningMethodRS256,
			KeyType:            openid4vp.KeyTypeRSA,
		}, nil
	case *ecdsa.PrivateKey:
		return &openid4vp.KeyPair{
			PrivateKey:         key,
			PublicKey:          &key.PublicKey,
			SigningMethodToUse: jwt.SigningMethodES256,
			KeyType:            openid4vp.KeyTypeEC,
		}, nil
	case ed25519.PrivateKey:
		return &openid4vp.KeyPair{
			PrivateKey:         key,
			PublicKey:          key.Public(),
			SigningMethodToUse: jwt.SigningMethodEdDSA,
			KeyType:            openid4vp.KeyTypeEd25519,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

func parseRawEd25519(b []byte) (ed25519.PrivateKey, bool) {
	// A raw Ed25519 private key should be 64 bytes (private + public part)
	if len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), true
	}
	return nil, false
}

func loadCertFromPEMFile(filepath string) (*openid4vp.CertData, error) {
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("could not read cert file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	_, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}

	return &openid4vp.CertData{
		CertPEM: pemData,
		CertDER: block.Bytes,
	}, nil
}

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
	"os"
	"strings"
	"vc/internal/verifier/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
)

// Client holds the public api object
type Client struct {
	cfg              *model.Cfg
	db               *db.Service
	log              *logger.Log
	verifierKeyPair  *openid4vp.KeyPair
	verifierX509Cert *openid4vp.CertData

	trustService *openid4vp.TrustService

	//TODO: remove after mongodb is being used to provide a tread-safe new next sequence
	currentSequence int64
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg: cfg,
		db:  db,
		log: log.New("apiv1"),
	}

	c.trustService = &openid4vp.TrustService{}

	//TODO: config value for private key file path + cert file path
	keyPair, err := LoadKeyPairFromPEMFile("/private_verifier_rsa.pem")
	if err != nil {
		c.log.Error(err, "Failed to load verifier key pair from pem file")
		return nil, err
	}
	c.verifierKeyPair = keyPair

	cert, err := c.loadCertFromPEMFile("/verifier_x509_cert.pem")
	if err != nil {
		c.log.Error(err, "Failed to load x509 certificate from pem file")
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

	privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return buildKeyPair(privKey)
	}

	if rsaKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
		return buildKeyPair(rsaKey)
	}

	if ecKey, err3 := x509.ParseECPrivateKey(block.Bytes); err3 == nil {
		return buildKeyPair(ecKey)
	}

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

func (c *Client) loadCertFromPEMFile(path string) (*openid4vp.CertData, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read cert PEM file: %w", err)
	}

	var (
		block         *pem.Block
		restOfPEMdata = pemData
		parseErrors   []error
	)

	for {
		block, restOfPEMdata = pem.Decode(restOfPEMdata)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("failed to parse cert: %w", err))
			continue
		}

		if !cert.IsCA {
			return &openid4vp.CertData{
				CertPEM: pem.EncodeToMemory(block),
				CertDER: cert.Raw,
			}, nil
		}
	}

	if len(parseErrors) > 0 {
		return nil, fmt.Errorf("no valid leaf certificate found, parse errors: %v", parseErrors)
	}

	return nil, errors.New("no leaf certificate found in PEM file")
}

package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"path/filepath"
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
	currentSequence  int64
}

// New creates a new instance of the public api
func New(ctx context.Context, db *db.Service, cfg *model.Cfg, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg: cfg,
		db:  db,
		log: log.New("apiv1"),
	}

	keyPair, err := loadKeyPair("/", "private_verifier_ec256.pem", "public_verifier_ec256.pem")
	if err != nil {
		c.log.Error(err, "Failed to load verifier key pair")
		return nil, err
	} else {
		_, ok := keyPair.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			err := errors.New("expected *ecdsa.PrivateKey")
			c.log.Error(err, "Wrong type of private key")
			return nil, err
		}
		_, ok = keyPair.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			err := errors.New("expected *ecdsa.PrivateKey")
			c.log.Error(err, "Wrong type of public key")
			return nil, err
		}
	}
	c.verifierKeyPair = keyPair
	c.verifierKeyPair.SigningMethodToUse = jwt.SigningMethodES256

	cert, err := loadCert("/verifier_x509_cert.pem")
	if err != nil {
		c.log.Error(err, "Failed to load x509 certificate")
		return nil, err
	}
	c.verifierX509Cert = cert

	c.log.Info("Started")

	return c, nil
}

func loadKeyPair(relativeBasePath, privateFilename, publicFilename string) (*openid4vp.KeyPair, error) {
	privatePath := filepath.Join(relativeBasePath, privateFilename)
	publicPath := filepath.Join(relativeBasePath, publicFilename)

	privateKey, err := loadPrivateKey(privatePath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	publicKey, err := loadPublicKey(publicPath)
	if err != nil {
		return nil, fmt.Errorf("load public key: %w", err)
	}

	return &openid4vp.KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("invalid PEM block for EC private key")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("invalid PEM block for public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return ecdsaPub, nil
}

func loadCert(path string) (*openid4vp.CertData, error) {
	pemData, err := os.ReadFile(path)
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

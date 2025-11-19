package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/auditlog"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg        *model.Cfg
	log        *logger.Log
	tracer     *trace.Tracer
	auditLog   *auditlog.Service
	privateKey any // Can be *ecdsa.PrivateKey or *rsa.PrivateKey
	publicKey  any // Can be *ecdsa.PublicKey or *rsa.PublicKey
	jwkClaim   jwt.MapClaims
	jwkBytes   []byte
	jwkProto   *apiv1_issuer.Jwk
	kid        string
}

// New creates a new instance of the public api
func New(ctx context.Context, auditLog *auditlog.Service, cfg *model.Cfg, tracer *trace.Tracer, log *logger.Log) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		log:      log.New("apiv1"),
		tracer:   tracer,
		auditLog: auditLog,
		jwkProto: &apiv1_issuer.Jwk{},
		jwkClaim: jwt.MapClaims{},
	}

	if err := c.initKeys(ctx); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *Client) initKeys(ctx context.Context) error {
	keyByte, err := os.ReadFile(c.cfg.Issuer.SigningKeyPath)
	if err != nil {
		c.log.Error(err, "Failed to read signing key")
		return err
	}

	if keyByte == nil {
		return helpers.ErrPrivateKeyMissing
	}

	// Try to parse as PKCS8 first (supports both RSA and ECDSA)
	c.privateKey, err = c.parsePrivateKey(keyByte)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// Extract public key based on key type
	switch key := c.privateKey.(type) {
	case *ecdsa.PrivateKey:
		c.publicKey = &key.PublicKey
	case *rsa.PrivateKey:
		c.publicKey = &key.PublicKey
	default:
		return fmt.Errorf("unsupported key type: %T", c.privateKey)
	}

	if err := c.createJWK(ctx); err != nil {
		return err
	}

	return nil
}

// parsePrivateKey attempts to parse a private key from PEM format
// Supports ECDSA and RSA keys in various formats (PKCS8, PKCS1, EC)
func (c *Client) parsePrivateKey(keyByte []byte) (any, error) {
	block, _ := pem.Decode(keyByte)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format first (preferred, supports both RSA and ECDSA)
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try EC private key format
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS1 RSA private key format
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try using jwt library's parser as fallback for EC keys
	if key, err := jwt.ParseECPrivateKeyFromPEM(keyByte); err == nil {
		return key, nil
	}

	// Try using jwt library's parser as fallback for RSA keys
	if key, err := jwt.ParseRSAPrivateKeyFromPEM(keyByte); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unable to parse private key in any supported format")
}

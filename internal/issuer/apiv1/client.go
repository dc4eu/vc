package apiv1

import (
	"context"
	"crypto/ecdsa"
	"os"
	"time"
	"vc/internal/issuer/auditlog"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
	"github.com/masv3971/gosdjwt"
)

//	@title		Issuer API
//	@version	0.1.0
//	@BasePath	/issuer/api/v1

// Client holds the public api object
type Client struct {
	cfg        *model.Cfg
	log        *logger.Log
	tp         *trace.Tracer
	auditLog   *auditlog.Service
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey

	ehicClient *ehicClient
	pda1Client *pda1Client
}

// New creates a new instance of the public api
func New(ctx context.Context, auditLog *auditlog.Service, cfg *model.Cfg, tracer *trace.Tracer, logger *logger.Log) (*Client, error) {
	c := &Client{
		cfg:      cfg,
		log:      logger,
		tp:       tracer,
		auditLog: auditLog,
	}

	var err error
	c.ehicClient, err = newEHICClient(ctx, tracer, c.log.New("ehic"))
	if err != nil {
		return nil, err
	}

	c.pda1Client, err = newPDA1Client(tracer, c, c.log.New("pda1"))
	if err != nil {
		return nil, err
	}

	if err := c.initKeys(); err != nil {
		return nil, err
	}

	c.log.Info("Started")

	return c, nil
}

func (c *Client) initKeys() error {
	keyByte, err := os.ReadFile(c.cfg.Issuer.SigningKeyPath)
	if err != nil {
		c.log.Error(err, "Failed to read signing key, please create a ECDSA prime256v1 key and save it to the path")
		return err
	}

	privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyByte)
	if err != nil {
		return err
	}

	c.privateKey = privateKey

	c.publicKey = &c.privateKey.PublicKey

	return nil
}

func (c *Client) sign(instruction gosdjwt.InstructionsV2) (*gosdjwt.SDJWT, error) {
	jwtConfig := &gosdjwt.Config{
		ISS: c.cfg.Issuer.JWTAttribute.Issuer,
		VCT: c.cfg.Issuer.JWTAttribute.VerifiableCredentialType,
	}

	if c.cfg.Issuer.JWTAttribute.EnableNotBefore {
		jwtConfig.NBF = time.Now().Unix()
		jwtConfig.EXP = time.Now().Add(time.Duration(c.cfg.Issuer.JWTAttribute.ValidDuration) * time.Second).Unix()
	}

	if c.cfg.Issuer.JWTAttribute.Status != "" {
		jwtConfig.Status = c.cfg.Issuer.JWTAttribute.Status
	}

	signedCredential, err := instruction.SDJWT(jwt.SigningMethodES256, c.privateKey, jwtConfig)
	if err != nil {
		return nil, err
	}

	return signedCredential, nil
}

package apiv1

import (
	"context"
	"crypto/ecdsa"
	"os"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/internal/issuer/auditlog"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwt"
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
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	jwkClaim   jwt.MapClaims
	jwkBytes   []byte
	jwkProto   *apiv1_issuer.Jwk
	kid        string

	ehicClient                 *ehicClient
	pda1Client                 *pda1Client
	elmClient                  *elmClient
	diplomaClient              *diplomaClient
	openBadgeCompleteClient    *openbadgeCompleteClient
	openBadgeBasicClient       *openbadgeBasicClient
	OpenBadgeEndorsementClient *openbadgeEndorsementsClient
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

	var err error
	c.ehicClient, err = newEHICClient(c, tracer, c.log.New("ehic"))
	if err != nil {
		return nil, err
	}

	c.pda1Client, err = newPDA1Client(c, tracer, c.log.New("pda1"))
	if err != nil {
		return nil, err
	}

	c.elmClient, err = newElmClient(c, tracer, c.log.New("elm"))
	if err != nil {
		return nil, err
	}

	c.diplomaClient, err = newDiplomaClient(c, tracer, c.log.New("diploma"))
	if err != nil {
		return nil, err
	}

	c.openBadgeCompleteClient, err = newOpenbadgeCompleteClient(c, tracer, c.log.New("openbadgeComplete"))
	if err != nil {
		return nil, err
	}

	c.openBadgeBasicClient, err = newOpenbadgeBasicClient(c, tracer, c.log.New("openbadgeBasic"))
	if err != nil {
		return nil, err
	}

	c.OpenBadgeEndorsementClient, err = newOpenbadgeEndorsementsClient(c, tracer, c.log.New("openbadgeEndorsement"))
	if err != nil {
		return nil, err
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
		c.log.Error(err, "Failed to read signing key, please create a ECDSA prime256v1 key and save it to the path")
		return err
	}

	if keyByte == nil {
		return helpers.ErrPrivateKeyMissing
	}

	c.privateKey, err = jwt.ParseECPrivateKeyFromPEM(keyByte)
	if err != nil {
		return err
	}

	c.publicKey = &c.privateKey.PublicKey

	if err := c.createJWK(ctx); err != nil {
		return err
	}

	return nil
}

func (c *Client) sign(ctx context.Context, instruction sdjwt.InstructionsV2) (*sdjwt.SDJWT, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	jwtConfig := &sdjwt.Config{
		ISS: c.cfg.Issuer.JWTAttribute.Issuer,
		VCT: c.cfg.Issuer.JWTAttribute.VerifiableCredentialType,
		CNF: c.jwkClaim,
		Header: sdjwt.ConfigHeader{
			Typ: "sd-jwt",
			Kid: c.kid,
		},
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

func (c *Client) sign2(ctx context.Context, claims map[string]any) {

}

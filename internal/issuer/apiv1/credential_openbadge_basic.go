package apiv1

import (
	"context"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/education"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwt3"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
)

type openbadgeBasicClient struct {
	log                   *logger.Log
	tracer                *trace.Tracer
	client                *Client
	credentialConstructor *model.CredentialConstructor
}

func newOpenbadgeBasicClient(ctx context.Context, client *Client, tracer *trace.Tracer, log *logger.Log) (*openbadgeBasicClient, error) {
	c := &openbadgeBasicClient{
		client: client,
		log:    log,
		tracer: tracer,
	}
	c.credentialConstructor = client.cfg.CredentialConstructor["openbadge_basic"]
	if err := c.credentialConstructor.LoadFile(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *openbadgeBasicClient) sdjwt(ctx context.Context, doc *education.OpenbadgeBasicDocument, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, span := c.tracer.Start(ctx, "apiv1:DiplomaClient:sdjwt")
	defer span.End()

	body, err := doc.Marshal()
	if err != nil {
		return "", err
	}

	vct := "EduOpenBadgeBasicCredential"

	body["nbf"] = int64(time.Now().Unix())
	body["exp"] = time.Now().Add(365 * 24 * time.Hour).Unix()
	body["iss"] = c.client.cfg.Issuer.JWTAttribute.Issuer
	body["_sd_alg"] = "sha-256"
	body["vct"] = vct

	body["cnf"] = map[string]any{
		"jwk": jwk,
	}

	header := map[string]any{
		"typ": "vc+sd-jwt",
		"kid": c.client.kid,
		"alg": "ES256",
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	ds := []string{}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

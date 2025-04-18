package apiv1

import (
	"context"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
	"vc/pkg/sdjwt3"
	"vc/pkg/trace"

	"github.com/golang-jwt/jwt/v5"
)

type diplomaClient struct {
	log    *logger.Log
	tracer *trace.Tracer
	client *Client
}

func newDiplomaClient(client *Client, tracer *trace.Tracer, log *logger.Log) (*diplomaClient, error) {
	c := &diplomaClient{
		client: client,
		log:    log,
		tracer: tracer,
	}

	return c, nil
}

func (c *diplomaClient) sdjwt(ctx context.Context, body map[string]any, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	ctx, span := c.tracer.Start(ctx, "apiv1:DiplomaClient:sdjwt")
	defer span.End()

	vct := "DiplomaCredential"

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

	var err error
	header["vctm"], err = c.MetadataClaim(vct)
	if err != nil {
		return "", err
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	ds := []string{}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

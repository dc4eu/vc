package apiv1

import (
	"context"
	"crypto/sha256"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/education"
	"vc/pkg/logger"
	"vc/pkg/sdjwt3"
	"vc/pkg/trace"

	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/golang-jwt/jwt/v5"
)

type elmClient struct {
	log    *logger.Log
	tracer *trace.Tracer
	client *Client
}

func newElmClient(client *Client, tracer *trace.Tracer, log *logger.Log) (*elmClient, error) {
	c := &elmClient{
		client: client,
		log:    log,
		tracer: tracer,
	}

	return c, nil
}

func (c *elmClient) sdjwt(ctx context.Context, doc *education.ELMDocument, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	_, span := c.tracer.Start(ctx, "apiv1:EmrexClient:sdjwt")
	defer span.End()

	body, err := doc.Marshal()
	if err != nil {
		return "", err
	}

	vct := "ELMCredential"

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

	header["vctm"], err = c.MetadataClaim(vct)
	if err != nil {
		return "", err
	}

	elmSelectiveDisclosure, err := disclosure.NewFromObject("elm", body["elm"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "elm")

	body["_sd"] = []string{
		string(elmSelectiveDisclosure.Hash(sha256.New())),
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	ds := []string{
		elmSelectiveDisclosure.EncodedValue,
	}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

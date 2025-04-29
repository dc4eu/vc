package apiv1

import (
	"context"
	"crypto/sha256"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwt3"
	"vc/pkg/trace"

	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/golang-jwt/jwt/v5"
)

type pidClient struct {
	log    *logger.Log
	tracer *trace.Tracer
	client *Client
}

func newPIDClient(client *Client, tracer *trace.Tracer, log *logger.Log) (*pidClient, error) {
	c := &pidClient{
		client: client,
		log:    log,
		tracer: tracer,
	}

	return c, nil
}

func (c *pidClient) sdjwt(ctx context.Context, doc *model.PIDDocument, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	body, err := doc.Marshal()
	if err != nil {
		return "", err
	}

	vct := "PID"

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

	firstName, err := disclosure.NewFromObject("first_name", body["first_name"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "first_name")

	familyName, err := disclosure.NewFromObject("family_name", body["family_name"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "family_name")

	dateOfBirth, err := disclosure.NewFromObject("date_of_birth", body["date_of_birth"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "date_of_birth")

	body["_sd"] = []string{
		string(firstName.Hash(sha256.New())),
		string(familyName.Hash(sha256.New())),
		string(dateOfBirth.Hash(sha256.New())),
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	// all attributes are selective disclosure
	ds := []string{
		firstName.EncodedValue,
		familyName.EncodedValue,
		dateOfBirth.EncodedValue,
	}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

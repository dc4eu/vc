package apiv1

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/sdjwt3"
	"vc/pkg/socialsecurity"
	"vc/pkg/trace"

	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/golang-jwt/jwt/v5"
)

type ehicClient struct {
	log                   *logger.Log
	tracer                *trace.Tracer
	client                *Client
	credentialConstructor *model.CredentialConstructor
}

func newEHICClient(ctx context.Context, client *Client, tracer *trace.Tracer, log *logger.Log) (*ehicClient, error) {
	c := &ehicClient{
		client: client,
		log:    log,
		tracer: tracer,
	}

	var ok bool
	c.credentialConstructor, ok = c.client.cfg.CredentialConstructor["ehic"]
	if !ok {
		return nil, errors.New("ehic credential constructor not found")
	}

	if err := c.credentialConstructor.LoadFile(ctx); err != nil {
		return nil, err
	}

	c.log.Debug("ehic", "vctm", c.credentialConstructor.VCTM)

	return c, nil
}

func (c *ehicClient) sdjwt(ctx context.Context, doc *socialsecurity.EHICDocument, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, span := c.tracer.Start(ctx, "apiv1:EHICClient:sdjwt")
	defer span.End()

	body, err := doc.Marshal()
	if err != nil {
		return "", err
	}

	body["nbf"] = int64(time.Now().Unix())
	body["exp"] = time.Now().Add(365 * 24 * time.Hour).Unix()
	body["iss"] = c.client.cfg.Issuer.JWTAttribute.Issuer
	body["_sd_alg"] = "sha-256"
	body["vct"] = c.credentialConstructor.VCT

	body["cnf"] = map[string]any{
		"jwk": jwk,
	}

	header := map[string]any{
		"typ": "vc+sd-jwt",
		"kid": c.client.kid,
		"alg": "ES256",
	}

	header["vctm"], err = c.credentialConstructor.VCTM.Encode()
	if err != nil {
		return "", err
	}

	subjectSelectiveDisclosure, err := disclosure.NewFromObject("subject", body["subject"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "subject")

	socialSecurityPinDisclosure, err := disclosure.NewFromObject("social_security_pin", body["social_security_pin"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "social_security_pin")

	periodEntitlementDisclosure, err := disclosure.NewFromObject("period_entitlement", body["period_entitlement"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "period_entitlement")

	documentIDDisclosure, err := disclosure.NewFromObject("document_id", body["document_id"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "document_id")

	competentInstitutionDisclosure, err := disclosure.NewFromObject("competent_institution", body["competent_institution"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "competent_institution")

	body["_sd"] = []string{
		string(subjectSelectiveDisclosure.Hash(sha256.New())),
		string(socialSecurityPinDisclosure.Hash(sha256.New())),
		string(periodEntitlementDisclosure.Hash(sha256.New())),
		string(documentIDDisclosure.Hash(sha256.New())),
		string(competentInstitutionDisclosure.Hash(sha256.New())),
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	ds := []string{
		subjectSelectiveDisclosure.EncodedValue,
		socialSecurityPinDisclosure.EncodedValue,
		periodEntitlementDisclosure.EncodedValue,
		documentIDDisclosure.EncodedValue,
		competentInstitutionDisclosure.EncodedValue,
	}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

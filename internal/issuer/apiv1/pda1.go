package apiv1

import (
	"context"
	"crypto/sha256"
	"time"
	"vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
	"vc/pkg/sdjwt3"
	"vc/pkg/socialsecurity"
	"vc/pkg/trace"

	"github.com/MichaelFraser99/go-sd-jwt/disclosure"
	"github.com/golang-jwt/jwt/v5"
)

type pda1Client struct {
	log    *logger.Log
	tracer *trace.Tracer
	client *Client
}

func newPDA1Client(client *Client, tracer *trace.Tracer, log *logger.Log) (*pda1Client, error) {
	c := &pda1Client{
		client: client,
		log:    log,
		tracer: tracer,
	}

	return c, nil
}

func (c *pda1Client) sdjwt(ctx context.Context, doc *socialsecurity.PDA1Document, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	body, err := doc.Marshal()
	if err != nil {
		return "", err
	}

	vct := "PDA1Credential"

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

	placesOfWorkDisclosure, err := disclosure.NewFromObject("places_of_work", body["places_of_work"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "places_of_work")

	socialSecurityNumberDisclosure, err := disclosure.NewFromObject("social_security_pin", body["social_security_pin"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "social_security_pin")

	nationalityDisclosure, err := disclosure.NewFromObject("nationality", body["nationality"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "nationality")

	detailsOfEmploymentDisclosure, err := disclosure.NewFromObject("details_of_employment", body["details_of_employment"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "details_of_employment")

	decisionLegislationApplicableDisclosure, err := disclosure.NewFromObject("decision_legislation_applicable", body["decision_legislation_applicable"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "decision_legislation_applicable")

	statusConfirmationDisclosure, err := disclosure.NewFromObject("status_confirmation", body["status_confirmation"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "status_confirmation")

	uniqueNumberOfIssuedDocumentDisclosure, err := disclosure.NewFromObject("unique_number_of_issued_document", body["unique_number_of_issued_document"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "unique_number_of_issued_document")

	competentInstitutionDisclosure, err := disclosure.NewFromObject("competent_institution", body["competent_institution"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "competent_institution")

	personDisclosure, err := disclosure.NewFromObject("person", body["person"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "person")

	body["_sd"] = []string{
		string(placesOfWorkDisclosure.Hash(sha256.New())),
		string(socialSecurityNumberDisclosure.Hash(sha256.New())),
		string(nationalityDisclosure.Hash(sha256.New())),
		string(detailsOfEmploymentDisclosure.Hash(sha256.New())),
		string(decisionLegislationApplicableDisclosure.Hash(sha256.New())),
		string(statusConfirmationDisclosure.Hash(sha256.New())),
		string(uniqueNumberOfIssuedDocumentDisclosure.Hash(sha256.New())),
		string(competentInstitutionDisclosure.Hash(sha256.New())),
		string(personDisclosure.Hash(sha256.New())),
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	ds := []string{
		placesOfWorkDisclosure.EncodedValue,
		socialSecurityNumberDisclosure.EncodedValue,
		nationalityDisclosure.EncodedValue,
		detailsOfEmploymentDisclosure.EncodedValue,
		decisionLegislationApplicableDisclosure.EncodedValue,
		statusConfirmationDisclosure.EncodedValue,
		uniqueNumberOfIssuedDocumentDisclosure.EncodedValue,
		competentInstitutionDisclosure.EncodedValue,
		personDisclosure.EncodedValue,
	}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

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
	log                   *logger.Log
	tracer                *trace.Tracer
	client                *Client
	credentialConstructor *model.CredentialConstructor
}

func newPIDClient(ctx context.Context, client *Client, tracer *trace.Tracer, log *logger.Log) (*pidClient, error) {
	c := &pidClient{
		client: client,
		log:    log,
		tracer: tracer,
	}

	c.credentialConstructor = client.cfg.CredentialConstructor["pid"]
	if err := c.credentialConstructor.LoadFile(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *pidClient) sdjwt(ctx context.Context, doc *model.Identity, jwk *apiv1_issuer.Jwk, salt *string) (string, error) {
	_, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

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

	givenName, err := disclosure.NewFromObject("given_name", body["given_name"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "given_name")

	familyName, err := disclosure.NewFromObject("family_name", body["family_name"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "family_name")

	birthDate, err := disclosure.NewFromObject("birthdate", body["birth_date"], salt) // What key to use?
	if err != nil {
		return "", err
	}
	delete(body, "birth_date")

	birthPlace, err := disclosure.NewFromObject("birth_place", body["birth_place"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "birth_place")

	nationality, err := disclosure.NewFromObject("nationality", body["nationality"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "nationality")

	personalAdministrativeNumber, err := disclosure.NewFromObject("personal_administrative_number", body["personal_administrative_number"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "personal_administrative_number")

	picture, err := disclosure.NewFromObject("picture", body["picture"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "picture")

	birthFamilyName, err := disclosure.NewFromObject("birth_family_name", body["birth_family_name"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "birth_family_name")

	birthGivenName, err := disclosure.NewFromObject("birth_given_name", body["birth_given_name"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "birth_given_name")

	sex, err := disclosure.NewFromObject("sex", body["sex"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "sex")

	emailAddress, err := disclosure.NewFromObject("email_address", body["email_address"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "email_address")

	mobilePhoneNumber, err := disclosure.NewFromObject("mobile_phone_number", body["mobile_phone_number"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "mobile_phone_number")

	residentAddress, err := disclosure.NewFromObject("resident_address", body["resident_address"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_address")

	residentStreetAddress, err := disclosure.NewFromObject("resident_street_address", body["resident_street_address"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_street_address")

	residentHouseNumber, err := disclosure.NewFromObject("resident_house_number", body["resident_house_number"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_house_number")

	residentPostalCode, err := disclosure.NewFromObject("resident_postal_code", body["resident_postal_code"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_postal_code")

	residentCity, err := disclosure.NewFromObject("resident_city", body["resident_city"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_city")

	residentState, err := disclosure.NewFromObject("resident_state", body["resident_state"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_state")

	residentCountry, err := disclosure.NewFromObject("resident_country", body["resident_country"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "resident_country")

	ageOver14, err := disclosure.NewFromObject("age_over_14", body["age_over_14"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_over_14")

	ageOver16, err := disclosure.NewFromObject("age_over_16", body["age_over_16"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_over_16")

	ageOver18, err := disclosure.NewFromObject("age_over_18", body["age_over_18"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_over_18")

	ageOver21, err := disclosure.NewFromObject("age_over_21", body["age_over_21"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_over_21")

	ageOver65, err := disclosure.NewFromObject("age_over_65", body["age_over_65"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_over_65")

	ageInYears, err := disclosure.NewFromObject("age_in_years", body["age_in_years"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_in_years")

	ageBirthYear, err := disclosure.NewFromObject("age_birth_year", body["age_birth_year"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "age_birth_year")

	issuanceDate, err := disclosure.NewFromObject("issuance_date", body["issuance_date"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "issuance_date")

	documentNumber, err := disclosure.NewFromObject("document_number", body["document_number"], salt)
	if err != nil {
		return "", err
	}
	delete(body, "document_number")

	body["_sd"] = []string{
		string(givenName.Hash(sha256.New())),
		string(familyName.Hash(sha256.New())),
		string(birthDate.Hash(sha256.New())),
		string(birthPlace.Hash(sha256.New())),
		string(nationality.Hash(sha256.New())),
		string(personalAdministrativeNumber.Hash(sha256.New())),
		string(picture.Hash(sha256.New())),
		string(birthFamilyName.Hash(sha256.New())),
		string(birthGivenName.Hash(sha256.New())),
		string(sex.Hash(sha256.New())),
		string(emailAddress.Hash(sha256.New())),
		string(mobilePhoneNumber.Hash(sha256.New())),
		string(residentAddress.Hash(sha256.New())),
		string(residentStreetAddress.Hash(sha256.New())),
		string(residentHouseNumber.Hash(sha256.New())),
		string(residentPostalCode.Hash(sha256.New())),
		string(residentCity.Hash(sha256.New())),
		string(residentState.Hash(sha256.New())),
		string(residentCountry.Hash(sha256.New())),
		string(ageOver14.Hash(sha256.New())),
		string(ageOver16.Hash(sha256.New())),
		string(ageOver18.Hash(sha256.New())),
		string(ageOver21.Hash(sha256.New())),
		string(ageOver65.Hash(sha256.New())),
		string(ageInYears.Hash(sha256.New())),
		string(ageBirthYear.Hash(sha256.New())),
		string(issuanceDate.Hash(sha256.New())),
		string(documentNumber.Hash(sha256.New())),
	}

	signedToken, err := sdjwt3.Sign(header, body, jwt.SigningMethodES256, c.client.privateKey)
	if err != nil {
		return "", err
	}

	// all attributes are selective disclosure
	ds := []string{
		givenName.EncodedValue,
		familyName.EncodedValue,
		birthDate.EncodedValue,
		birthPlace.EncodedValue,
		nationality.EncodedValue,
		personalAdministrativeNumber.EncodedValue,
		picture.EncodedValue,
		birthFamilyName.EncodedValue,
		birthGivenName.EncodedValue,
		sex.EncodedValue,
		emailAddress.EncodedValue,
		mobilePhoneNumber.EncodedValue,
		residentAddress.EncodedValue,
		residentStreetAddress.EncodedValue,
		residentHouseNumber.EncodedValue,
		residentPostalCode.EncodedValue,
		residentCity.EncodedValue,
		residentState.EncodedValue,
		residentCountry.EncodedValue,
		ageOver14.EncodedValue,
		ageOver16.EncodedValue,
		ageOver18.EncodedValue,
		ageOver21.EncodedValue,
		ageOver65.EncodedValue,
		ageInYears.EncodedValue,
		ageBirthYear.EncodedValue,
		issuanceDate.EncodedValue,
		documentNumber.EncodedValue,
	}

	signedToken = sdjwt3.Combine(signedToken, ds, "")

	return signedToken, nil
}

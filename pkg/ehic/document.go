package ehic

import (
	"vc/pkg/eidas"
)

// Document is the EHIC model
type Document struct {
	PID                  eidas.Identification `json:"pid" bson:"pid" validate:"required"`
	CardHolder           CardHolder           `json:"cardHolder" bson:"cardHolder" validate:"required"`
	CompetentInstitution CompetentInstitution `json:"competentInstitution" bson:"competentInstitution" validate:"required"`
	CardInformation      CardInformation      `json:"cardInformation" bson:"cardInformation" validate:"required"`
	Signature            Signature            `json:"signature" bson:"signature" validate:"required"`
}

// CardHolder is the EHIC card holder model, PID and CardHolder not necessarily need to be the same
type CardHolder struct {
	FamilyName       string `json:"familyName" bson:"familyName" validate:"required"`
	GivenName        string `json:"givenName" bson:"givenName" validate:"required"`
	BirthDate        string `json:"birthDate" bson:"birthDate" validate:"required"`
	ID               string `json:"id" bson:"id" validate:"required"`
	CardholderStatus string `json:"cardholderStatus" bson:"cardholderStatus" validate:"required"`
}

// CompetentInstitution is equivalent to Authentic Source
type CompetentInstitution struct {
	InstitutionName string `json:"institutionName" bson:"institutionName" validate:"required"`
	ID              string `json:"id" bson:"id" validate:"required"`
}

// CardInformation is the EHIC card information model
type CardInformation struct {
	ID           string    `json:"id" bson:"id" validate:"required"`
	IssuanceDate string    `json:"issuanceDate" bson:"issuanceDate" validate:"required"`
	ValidSince   string    `json:"validSince" bson:"validSince" validate:"required"`
	ExpiryDate   string    `json:"expiryDate" bson:"expiryDate" validate:"required"`
	InvalidSince string    `json:"invalidSince" bson:"invalidSince" validate:"required"`
	Signature    Signature `json:"signature" bson:"signature" validate:"required"`
}

// Signature is the EHIC signature model
type Signature struct {
	Issuer string `json:"issuer" bson:"issuer" validate:"required"`
	Seal   string `json:"seal" bson:"seal" validate:"required"`
}

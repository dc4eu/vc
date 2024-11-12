package ehic

import "encoding/json"

// Document is the EHIC model
type Document struct {
	Subject              Subject              `json:"subject" bson:"subject" validate:"required"`
	SocialSecurityPin    string               `json:"social_security_pin" bson:"socialSecurityPin" validate:"required"`
	PeriodEntitlement    PeriodEntitlement    `json:"period_entitlement" bson:"periodOfEntitlement" validate:"required"`
	DocumentID           string               `json:"document_id" bson:"documentID" validate:"required"`
	CompetentInstitution CompetentInstitution `json:"competent_institution" bson:"competent_institution" validate:"required"`
}

type Subject struct {
	Forename      string        `json:"forename" bson:"forename" validate:"required"`
	FamilyName    string        `json:"family_name" bson:"familyName" validate:"required"`
	DateOfBirth   string        `json:"date_of_birth" bson:"dateOfBirth" validate:"required"`
	OtherElements OtherElements `json:"other_elements" bson:"otherElements" validate:"required"`
}

type OtherElements struct {
	Sex               string `json:"sex" bson:"sex" validate:"required"`
	ForenameAtBirth   string `json:"forename_at_birth" bson:"forenameAtBirth" validate:"required"`
	FamilyNameAtBirth string `json:"family_name_at_birth" bson:"familyNameAtBirth" validate:"required"`
}

type PeriodEntitlement struct {
	StartingDate string `json:"starting_date" bson:"startingDate" validate:"required"`
	EndingDate   string `json:"ending_date" bson:"endingDate" validate:"required"`
}

type CompetentInstitution struct {
	InstitutionID      string `json:"institution_id" bson:"instidutionID" validate:"required"`
	InstitutionName    string `json:"institution_name" bson:"institutionName" validate:"required"`
	InstitutionCountry string `json:"institution_country" bson:"institutionCountry" validate:"required"`
}

// Marshal marshals the document to a map
func (d *Document) Marshal() (map[string]any, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	err = json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

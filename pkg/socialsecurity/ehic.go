package socialsecurity

import "encoding/json"

// EHICDocument is the EHIC model
type EHICDocument struct {
	PersonalAdministrativeNumber string           `json:"personal_administrative_number" bson:"personalAdministrativeNumber" validate:"required,min=4,max=50"`
	IssuingAuthority             IssuingAuthority `json:"issuing_authority" bson:"issuingAuthority" validate:"required"`
	IssuingCountry               string           `json:"issuing_country" bson:"issuingCountry" validate:"required,iso3166_1_alpha2"`
	DateOfExpiry                 string           `json:"date_of_expiry" bson:"dateOfExpiry" validate:"required"`
	DateOfIssuance               string           `json:"date_of_issuance" bson:"dateOfIssuance" validate:"required"`
	DocumentNumber               string           `json:"document_number" bson:"documentNumber" validate:"required,min=4,max=50"`
}

type IssuingAuthority struct {
	ID   string `json:"id" bson:"id" validate:"required,min=1,max=20"`
	Name string `json:"name" bson:"name" validate:"required,min=1,max=100"`
}

// Marshal marshals the document to a map
func (d *EHICDocument) Marshal() (map[string]any, error) {
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

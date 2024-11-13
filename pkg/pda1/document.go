package pda1

import "encoding/json"

// Document model for PDA1
type Document struct {
	SocialSecurityPin             string                        `json:"social_security_pin" bson:"social_security_pin"`
	Nationality                   []string                      `json:"nationality" bson:"nationality"`
	DetailsOfEmployment           []DetailsOfEmployment         `json:"details_of_employment" bson:"details_of_employment"`
	PlacesOfWork                  []PlacesOfWork                `json:"places_of_work" bson:"places_of_work"`
	DecisionLegislationApplicable DecisionLegislationApplicable `json:"decision_legislation_applicable" bson:"decision_legislation_applicable"`
	StatusConfirmation            string                        `json:"status_confirmation" bson:"status_confirmation"`
	UniqueNumberOfIssuedDocument  string                        `json:"unique_number_of_issued_document" bson:"unique_number_of_issued_document"`
	CompetentInstitution          CompetentInstitution          `json:"competent_institution" bson:"competent_institution"`
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

// DetailsOfEmployment is the model for the PDA1 details of employment
type DetailsOfEmployment struct {
	TypeOfEmployment string             `json:"type_of_employment" bson:"type_of_employment"`
	Name             string             `json:"name" bson:"name"`
	Address          AddressWithCountry `json:"address" bson:"address"`
	IDsOfEmployer    []IDsOfEmployer    `json:"ids_of_employer" bson:"ids_of_employer"`
}

// AddressWithCountry is the model for the PDA1 address type with country
type AddressWithCountry struct {
	Street   string `json:"street" bson:"street"`
	PostCode string `json:"post_code" bson:"post_code"`
	Town     string `json:"town" bson:"town"`
	Country  string `json:"country" bson:"country"`
}

// Address is the model for the PDA1 address type
type Address struct {
	Street   string `json:"street" bson:"street"`
	PostCode string `json:"post_code" bson:"post_code"`
	Town     string `json:"town" bson:"town"`
}

// IDsOfEmployer is the model for the PDA1 IDs of employer
type IDsOfEmployer struct {
	EmployerID string `json:"employer_id" bson:"employer_id"`
	TypeOfID   string `json:"type_of_id" bson:"type_of_id"`
}

type PlacesOfWork struct {
	NoFixedPlaceOfWorkExist bool          `json:"no_fixed_place_of_work_exist" bson:"no_fixed_place_of_work_exist"`
	CountryWork             string        `json:"country_work" bson:"country_work"`
	PlaceOfWork             []PlaceOfWork `json:"place_of_work" bson:"place_of_work"`
}

type PlaceOfWork struct {
	CompanyVesselName string         `json:"company_vessel_name" bson:"company_vessel_name"`
	FlagStateHomeBase string         `json:"flag_state_home_base" bson:"flag_state_home_base"`
	IDsOfCompany      []IDsOfCompany `json:"ids_of_company" bson:"ids_of_company"`
	Address           Address        `json:"address" bson:"address"`
}

type IDsOfCompany struct {
	CompanyID string `json:"company_id" bson:"company_id"`
	TypeOfID  string `json:"type_of_id" bson:"type_of_id"`
}

type DecisionLegislationApplicable struct {
	MemberStateWhichLegislationApplies string `json:"member_state_which_legislation_applies" bson:"member_state_which_legislation_applies"`
	TransitionalRuleApply              bool   `json:"transitional_rule_apply" bson:"transitional_rule_apply"`
	StartingDate                       string `json:"starting_date" bson:"starting_date"`
	EndingDate                         string `json:"ending_date" bson:"ending_date"`
}

type CompetentInstitution struct {
	InstitutionID   string `json:"institution_id" bson:"institution_id"`
	InstitutionName string `json:"institution_name" bson:"institution_name"`
	CountryCode     string `json:"country_code" bson:"country_code"`
}

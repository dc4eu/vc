package education

import "encoding/json"

type DiplomaDocument struct {
	DataOfBirth string `json:"date_of_birth" validate:"required"`
	FamilyName  string `json:"family_name" validate:"required"`
	GivenName   string `json:"given_name" validate:"required"`

	PersonalIdentifier PersonalIdentifier `json:"personal_identifier"`

	NameOfAwardingTertiaryEducationInstitution string `json:"name_of_awarding_tertiary_education_institution" validate:"required"`

	NameOfQualification                             string `json:"name_of_qualification" validate:"required"`
	DateOfAward                                     string `json:"date_of_award" validate:"required"`
	CountryOfAwardOfAcademicQualification           string `json:"country_of_award_of_academic_qualification"`
	OverallClassificationOfTheAcademicQualification string `json:"overall_classification_of_the_academic_qualification" validate:"required"`
	NameOfQualificationStudyField                   string `json:"name_of_qualification_study_field"`
	DegreeProjectTitle                              string `json:"degree_project_title"`
	Entitlement                                     string `json:"entitlement"`
	OtherInformation                                string `json:"other_information"`
}

func (d *DiplomaDocument) Marshal() (map[string]any, error) {
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

type PersonalIdentifier struct {
	NationalIDNumber string `json:"national_id_number"`
	Citizenship      string `json:"citizenship"`
	DateOfBirth      string `json:"date_of_birth"`
	Gender           string `json:"gender"`
	GroupMemberOf    string `json:"group_member_of"`
	HasClaim         string `json:"has_claim"`
	HasCredential    string `json:"has_credential"`
	PlaceOfBirth     string `json:"place_of_birth"`
}

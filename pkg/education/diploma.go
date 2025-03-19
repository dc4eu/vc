package education

import "encoding/json"

type DiplomaDocument struct {
	DataOfBirth                                     string `json:"date_of_birth" validate:"required"`
	FamilyName                                      string `json:"family_name" validate:"required"`
	GivenName                                       string `json:"given_name" validate:"required"`
	PersonalIdentifier                              string `json:"personal_identifier"`
	NameOfAwardingTertiaryEducationInstitution      string `json:"name_of_awarding_tertiary_education_institution" validate:"required"`
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

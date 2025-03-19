package education

import "encoding/json"

type MicrocredentialDocument struct {
	IdentificationOfTheLearner IdentificationOfTheLearner `json:"identification_of_the_learner" validate:"required"`
	TitleOfTheMicroCredential  TitleOfTheMicroCredential  `json:"title_of_the_micro_credential" validate:"required"`
	CountryOrRegionOfTheIssuer CountryOrRegionOfTheIssuer `json:"country_or_region_of_the_issuer" validate:"required"`
	AwardingBody               AwardingBody               `json:"awarding_body" validate:"required"`
	DateOfIssuing              string                     `json:"dateOfIssuing" validate:"required"`
	LearningOutcomes           LearningOutcomes           `json:"learning_outcomes" validate:"required"`
	EducationLevel             EducationLevel             `json:"education_level" validate:"required"`
	TypeOfAssessment           TypeOfAssessment           `json:"type_of_assessment" validate:"required"`
	FormOfParticipation        FormOfParticipation        `json:"form_of_participation" validate:"required"`
	QualityAssurance           QualityAssurance           `json:"quality_assurance" validate:"required"`

	NotionalWorkload string `json:"notionalWorkload" validate:"required"`

	Prerequisites                      string `json:"prerequisites"`
	SupervisionAndIdentityVerification string `json:"supervisionAndIdentityVerification" validate:"required"`
	GradeAchieved                      string `json:"gradeAchieved" validate:"required"`
	IntegrationStackabilityOptions     string `json:"integrationStackabilityOptions" validate:"required"`
	Link                               string `json:"link" validate:"required"`
}

type IdentificationOfTheLearner struct {
	Citizenship        string `json:"citizenship" validate:"required"`
	GivenNames         string `json:"givenNames" validate:"required"`
	FamilyName         string `json:"familyName" validate:"required"`
	NationalId         string `json:"nationalId" validate:"required"`
	DateOfBirth        string `json:"dateOfBirth" validate:"required"`
	ContactInformation string `json:"contactInformation" validate:"required"`
}

type TitleOfTheMicroCredential struct {
	ISCEDCode string `json:"iscedCode" validate:"required"`
	Title     string `json:"title" validate:"required"`
}

type CountryOrRegionOfTheIssuer struct {
	Country string `json:"country" validate:"required"`
}

type AwardingBody struct {
	TaxIdentifier string `json:"taxIdentifier" validate:"required"`
	Title         string `json:"title" validate:"required"`
	LegalName     string `json:"legalName" validate:"required"`
	URL           string `json:"url" validate:"required"`
}

type LearningOutcomes struct {
	MoreInformation   string `json:"moreInformation" validate:"required"`
	RelatedESCOSkills string `json:"relatedESCOskills" validate:"required"`
	RelatedSkills     string `json:"relatedSkills" validate:"required"`
	ReusabilityLevel  string `json:"reusabilityLevel" validate:"required"`
	Title             string `json:"title" validate:"required"`
	Type              string `json:"type" validate:"required"`
}

type EducationLevel struct {
	EducationSubject string `json:"educationSubject" validate:"required"`
	EducationLevel   string `json:"educationLevel" validate:"required"`
	EQFLevel         string `json:"eqfLevel" validate:"required"`
	QFLevel          string `json:"qfLevel" validate:"required"`
}

type TypeOfAssessment struct {
	Type        string `json:"type" validate:"required"`
	Description string `json:"description" validate:"required"`
	Grade       string `json:"grade" validate:"required"`
}

type FormOfParticipation struct {
	Type string `json:"type" validate:"required"`
	Mode string `json:"mode" validate:"required"`
}

type QualityAssurance struct {
	Identifier string `json:"identifier" validate:"required"`
	Title      string `json:"title" validate:"required"`
	Type       string `json:"type" validate:"required"`
}

func (d *MicrocredentialDocument) Marshal() (map[string]any, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}

	var doc map[string]interface{}
	err = json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

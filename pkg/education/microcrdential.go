package education

import "encoding/json"

type MicroCredentialDocument struct {
	Context           []string             `json:"@context" validate:"required"`
	ID                string               `json:"id" validate:"required"`
	Type              []string             `json:"type" validate:"required"`
	Issuer            MCIssuer             `json:"issuer" validate:"required"`
	ValidFrom         string               `json:"validFrom" validate:"required"`
	ValidUntil        string               `json:"validUntil" validate:"required"`
	CredentialSubject MCCredentialSubject  `json:"credentialSubject" validate:"required"`
	CredentialSchema  []MCCredentialSchema `json:"credentialSchema" validate:"required"`
}

type MCCredentialSchema struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
}

type MCResult struct {
	Type              []string `json:"type" validate:"required"`
	ResultDescription string   `json:"resultDescription" validate:"required"`
	Value             string   `json:"value" validate:"required"`
}

type MCCredentialSubject struct {
	ID          string        `json:"id" validate:"required"`
	Type        []string      `json:"type" validate:"required"`
	Achievement MCAchievement `json:"achievement" validate:"required"`
	Result      []MCResult    `json:"result" validate:"required"`
}

type MCAchievement struct {
	ID                         string                `json:"id" validate:"required"`
	Type                       []string              `json:"type" validate:"required"`
	Criteria                   MCCriteria            `json:"criteria" validate:"required"`
	Description                string                `json:"description" validate:"required"`
	Name                       string                `json:"name" validate:"required"`
	Image                      MCImage               `json:"image" validate:"required"`
	InLanguage                 string                `json:"inLanguage" validate:"required"`
	EducationProgramIdentifier int                   `json:"educationProgramIdentifier" validate:"required"`
	SBU                        int                   `json:"sbu" validate:"required"`
	Alignment                  []MCAlignment         `json:"alignment" validate:"required"`
	ParticipationType          string                `json:"participationType" validate:"required"`
	AssessmentType             string                `json:"assessmentType" validate:"required"`
	IdentityChecked            bool                  `json:"identityChecked" validate:"required"`
	SupervisionType            string                `json:"supervisionType" validate:"required"`
	ResultDescription          []MCResultDescription `json:"resultDescription" validate:"required"`
}

type MCResultDescription struct {
	ID            string   `json:"id" validate:"required"`
	Type          []string `json:"type" validate:"required"`
	ValueMax      string   `json:"valueMax" validate:"required"`
	ValueMin      string   `json:"valueMin" validate:"required"`
	Name          string   `json:"name" validate:"required"`
	RequiredValue string   `json:"requiredValue" validate:"required"`
	ResultType    string   `json:"resultType" validate:"required"`
}

type MCAlignment struct {
	Type       []string `json:"type" validate:"required"`
	TargetType string   `json:"targetType" validate:"required"`
	TargetName string   `json:"targetName" validate:"required"`
	TargetURL  string   `json:"targetURL" validate:"required"`
}

type MCImage struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
}

type MCCriteria struct {
	Narrative string `json:"narrative" validate:"required"`
}

type MCIssuer struct {
	ID      string          `json:"id" validate:"required"`
	Type    []string        `json:"type" validate:"required"`
	Name    string          `json:"name" validate:"required"`
	Address MCIssuerAddress `json:"address" validate:"required"`
}

type MCIssuerAddress struct {
	Type               []string `json:"type" validate:"required"`
	AddressCountry     string   `json:"addressCountry" validate:"required"`
	AddressCountryCode string   `json:"addressCountryCode" validate:"required"`
	StreetAddress      string   `json:"streetAddress" validate:"required"`
	PostalCode         string   `json:"postalCode" validate:"required"`
}

func (d *MicroCredentialDocument) Marshal() (map[string]any, error) {
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

package apiv1

import (
	"fmt"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
)

var format = map[string]openid4vp.Format{
	"vc+sd-jwt": {Alg: []string{"ES256"}},
}

var presentationRequestTypes = map[string]*openid4vp.PresentationRequestType{
	"VCELM": {
		ID:          "VCELM",
		Title:       "VC European Learning Model for EMREX",
		Description: "Required Fields: VC type, ELM",
	},
	"VCEHIC": {
		ID:          "VCEHIC",
		Title:       "VC European Health Insurance Card",
		Description: "Request a VC European Health Insurance Card",
	},
	"VCPID": {
		ID:          "VCPID",
		Title:       "VC PID",
		Description: "Request a VC PID",
	},

	"EuropeanHealthInsuranceCard": {
		ID:          "EuropeanHealthInsuranceCard",
		Title:       "European Health Insurance Card - based on wwWallet issuer",
		Description: "Request a European Health Insurance Card",
	},
	//"CustomVerifiableId": {
	//	ID:          "CustomVerifiableId",
	//	Title:       "PID  (ARF v1.8) - based on wwWallet issuer",
	//	Description: "Request a PID (ARF v1.8)",
	//},
	"MinimalPIDAndEuropeanHealthInsuranceCard": {
		ID:          "MinimalPIDAndEuropeanHealthInsuranceCard",
		Title:       "PID (ARF v1.8) + EHIC - both based on wwWallet issuer",
		Description: "Request a PID (ARF v1.8) along with an EHIC",
	},
}

func lookupPresentationRequestTypeFrom(ID string) (*openid4vp.PresentationRequestType, bool) {
	prt, ok := presentationRequestTypes[ID]
	return prt, ok
}

func buildPresentationDefinition(presentationRequestType *openid4vp.PresentationRequestType) (*openid4vp.PresentationDefinition, error) {
	switch presentationRequestType.ID {
	case "VCELM":
		return vcELMForEMREX(presentationRequestType), nil
	case "VCEHIC":
		return vcEHIC(presentationRequestType), nil
	case "VCPID":
		return vcPID(presentationRequestType), nil
	case "EuropeanHealthInsuranceCard":
		return wwwEHIC(presentationRequestType), nil
	//case "CustomVerifiableId":
	//	return wwwPID18(presentationRequestType), nil
	case "MinimalPIDAndEuropeanHealthInsuranceCard":
		return wwwMinimalPIDAndEuropeanHealthInsuranceCard(presentationRequestType), nil
	default:
		return nil, fmt.Errorf("presentationRequestType.ID %s is currently not supported", presentationRequestType.ID)
	}
}

func vcELMForEMREX(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiElm1}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "ELM", Path: []string{"$.elm"}},
					},
				},
			},
		},
	}
}

func vcEHIC(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiEhic1}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Personal ID", Path: []string{"$.personal_administrative_number"}},
						{Name: "Document number", Path: []string{"$.document_number"}},
						{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						{Name: "Issuing authority id", Path: []string{"$.issuing_authority.id"}},
						{Name: "Issuing authority name", Path: []string{"$.issuing_authority.name"}},
						{Name: "Expiry date", Path: []string{"$.date_of_expiry"}},
						{Name: "Issue date", Path: []string{"$.date_of_issuance"}},
					},
				},
			},
		},
	}
}

func vcPID(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiPid1}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		Selectable:  true, // special field found i db4eu verifier
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Family name", Path: []string{"$.family_name"}},
						{Name: "Given name", Path: []string{"$.given_name"}},
						{Name: "Date of birth", Path: []string{"$.birthdate"}},
						{Name: "Place of birth", Path: []string{"$.birth_place"}},
						{Name: "Nationality", Path: []string{"$.nationality"}},
						{Name: "Issuing authority", Path: []string{"$.issuing_authority"}},
						{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						{Name: "Expiry date", Path: []string{"$.expiry_date"}},
						//TODO add more optional attributes for vcPID?
					},
				},
			},
		},
	}
}

func wwwEHIC(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	vctList := []string{"urn:eudi:ehic:1"}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     requestType.ID,
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Personal ID", Path: []string{"$.personal_administrative_number"}},
						{Name: "Document number", Path: []string{"$.document_number"}},
						{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						{Name: "Issuing authority id", Path: []string{"$.issuing_authority.id"}},
						{Name: "Issuing authority name", Path: []string{"$.issuing_authority.name"}},
						{Name: "Expiry Date", Path: []string{"$.date_of_expiry"}},
						{Name: "Issue Date", Path: []string{"$.date_of_issuance"}},
					},
				},
			},
		},
	}
}

func wwwMinimalPIDAndEuropeanHealthInsuranceCard(requestType *openid4vp.PresentationRequestType) *openid4vp.PresentationDefinition {
	pidVctList := []string{"urn:eudi:pid:1"}
	ehicVctList := []string{"urn:eudi:ehic:1"}

	return &openid4vp.PresentationDefinition{
		ID:          requestType.ID,
		Title:       requestType.Title,
		Description: requestType.Description,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "minimalSdJwtPID",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: pidVctList}},
						{Name: "Family name", Path: []string{"$.family_name"}},
						{Name: "Given name", Path: []string{"$.given_name"}},
						{Name: "Date of birth", Path: []string{"$.birthdate"}},
						//{Name: "Place of birth", Path: []string{"$.birth_place"}},
						//{Name: "Nationality", Path: []string{"$.nationalities"}},
						//{Name: "Issuing authority", Path: []string{"$.issuing_authority"}},
						//{Name: "Issuing country", Path: []string{"$.issuing_country"}},
						//{Name: "Expiry date", Path: []string{"$.date_of_expiry"}},
					},
				},
			},
			{
				ID:     "EuropeanHealthInsuranceCard",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: ehicVctList}},
						{Name: "Personal ID", Path: []string{"$.personal_administrative_number"}},
						{Name: "Document Number", Path: []string{"$.document_number"}},
					},
				},
			},
		},
	}
}

// DEPRECATED: use build buildPresentationDefinition()
func buildPresentationDefinitionFor(documentType string) (*openid4vp.PresentationDefinition, error) {
	switch documentType {
	case model.CredentialTypeUrnEudiDiploma1:
		return diploma(), nil
	case model.CredentialTypeUrnEudiEhic1:
		return ehic(), nil
	case model.CredentialTypeUrnEudiElm1:
		return elm(), nil
	case model.CredentialTypeUrnEudiMicroCredential1:
		return nil, fmt.Errorf("document type %s is currently not supported", documentType)
	case model.CredentialTypeUrnEudiPda11:
		return pda1(), nil
	case model.CredentialTypeUrnEudiPid1:
		return pid(), nil
	default:
		return nil, fmt.Errorf("document type %s is currently not supported", documentType)
	}
}

// DEPRECATED:
func diploma() *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiDiploma1}

	return &openid4vp.PresentationDefinition{
		ID:          "Bachelor",
		Title:       "Bachelor Diploma",
		Description: "Required Fields: VC type, Grade, EQF Level & Diploma Title",
		Format:      format,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "Bachelor",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Grade", Path: []string{"$.grade"}},
						{Name: "EQF Level", Path: []string{"$.eqf_level"}},
						{Name: "Diploma Title", Path: []string{"$.title"}},
					},
				},
			},
		},
	}
}

// DEPRECATED:
func ehic() *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiEhic1}

	return &openid4vp.PresentationDefinition{
		ID:          "EuropeanHealthInsuranceCard",
		Title:       "European HealthInsurance Card",
		Description: "Required Fields: VC type, SSN, Family Name, Given Name & Birth Date",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "EuropeanHealthInsuranceCard",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						//{Name: "Subject", Path: []string{"$.subject"}},
						{Name: "Given Name", Path: []string{"$.subject.forename"}},
						{Name: "Family Name", Path: []string{"$.subject.family_name"}},
						{Name: "Birthdate", Path: []string{"$.subject.date_of_birth"}},
						{Name: "SSN", Path: []string{"$.social_security_pin"}},
						//TODO: {Name: "Period entitlement", Path: []string{"$.period_entitlement"}},
						{Name: "Document ID", Path: []string{"$.document_id"}},
						{Name: "Competent Institution", Path: []string{"$.competent_institution.institution_name"}},
					},
				},
			},
		},
	}
}

// DEPRECATED:
func elm() *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiElm1}

	return &openid4vp.PresentationDefinition{
		ID:          "ELM",
		Title:       "European Learning Model for EMREX",
		Description: "Required Fields: VC type, ELM",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "ELM",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "ELM", Path: []string{"$.elm"}},
					},
				},
			},
		},
	}
}

// DEPRECATED:
func pda1() *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiPda11}

	return &openid4vp.PresentationDefinition{
		ID:          "PDA1",
		Title:       "PDA1",
		Description: "Required Fields: VC type, SSN, Member State of Application",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "PDA1",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "SSN", Path: []string{"$.social_security_pin"}},
						{Name: "Nationality", Path: []string{"$.nationality"}},
						{Name: "Member State of Application", Path: []string{"$.decision_legislation_applicable.member_state_which_legislation_applies"}},
					},
				},
			},
		},
	}
}

// DEPRECATED:
func pid() *openid4vp.PresentationDefinition {
	vctList := []string{model.CredentialTypeUrnEudiPid1}

	return &openid4vp.PresentationDefinition{
		ID:          "PID",
		Title:       "PID",
		Description: "Required Fields: VC type, Given Name ,Family Name, Birth Date",
		Selectable:  true, // special field found i db4eu verifier
		Format:      format,
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID:     "PID",
				Format: format,
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: vctList}},
						{Name: "Given Name", Path: []string{"$.given_name"}},
						{Name: "Family Name", Path: []string{"$.family_name"}},
						//TODO: birth_date??? - but wwW uses birthdate right now
						{Name: "Birth Date", Path: []string{"$.birthdate"}},
						//TODO: add birth_place, nationality
						//TODO: add pid-meta: expiry_date, issuing_authority, issuing_country
					},
				},
			},
		},
	}
}

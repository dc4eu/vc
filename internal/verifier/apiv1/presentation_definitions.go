package apiv1

import (
	"fmt"
	"vc/pkg/model"
	"vc/pkg/openid4vp"
)

var format = map[string]openid4vp.Format{
	"vc+sd-jwt": {Alg: []string{"ES256"}},
}

func buildPresentationDefinitionFor(documentType string) (*openid4vp.PresentationDefinition, error) {
	switch documentType {
	case "Diploma":
		return diploma(), nil
	case "EHIC":
		return ehic(), nil
	case "ELM":
		return elm(), nil
	case "MicroCredential":
		return nil, fmt.Errorf("document type %s is currently not supported", documentType)
	case "PDA1":
		return pda1(), nil
	case "PID":
		return pid(), nil
	default:
		return nil, fmt.Errorf("document type %s is currently not supported", documentType)
	}
}

func diploma() *openid4vp.PresentationDefinition {
	vctList := []string{
		"https://vc-interop-3.sunet.se/credential/diploma/1.0",
		"https://vc-interop-1.sunet.se/credential/diploma/1.0",
		"https://satosa-test-1.sunet.se/credential/diploma/1.0",
		"https://satosa-dev-1.sunet.se/credential/diploma/1.0",
		"urn:credential:diploma",
		"DiplomaCredential",
		"Diploma"}

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

func ehic() *openid4vp.PresentationDefinition {
	ehicVCTs := []string{
		"https://vc-interop-3.sunet.se/credential/ehic/1.0",
		"https://vc-interop-1.sunet.se/credential/ehic/1.0",
		"https://satosa-test-1.sunet.se/credential/ehic/1.0",
		"https://satosa-dev-1.sunet.se/credential/ehic/1.0",
		"urn:credential:ehic",
		model.CredentialTypeUrnEudiEhic1,
		"EHICCredential"}

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
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: ehicVCTs}},
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

func elm() *openid4vp.PresentationDefinition {
	vctList := []string{
		"https://vc-interop-3.sunet.se/credential/elm/1.0",
		"https://vc-interop-1.sunet.se/credential/elm/1.0",
		"https://satosa-test-1.sunet.se/credential/elm/1.0",
		"https://satosa-dev-1.sunet.se/credential/elm/1.0",
		"urn:credential:elm",
		"ELMCredential",
		"ElmCredential",
		"ELM",
		"elm"}

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

func pda1() *openid4vp.PresentationDefinition {
	pda1VCTs := []string{
		"https://vc-interop-3.sunet.se/credential/pda1/1.0",
		"https://vc-interop-1.sunet.se/credential/pda1/1.0",
		"https://satosa-test-1.sunet.se/credential/pda1/1.0",
		"https://satosa-dev-1.sunet.se/credential/pda1/1.0",
		"urn:credential:pda1",
		"urn:eudi:pda1:1",
		"PDA1Credential"}

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
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: pda1VCTs}},
						{Name: "SSN", Path: []string{"$.social_security_pin"}},
						{Name: "Nationality", Path: []string{"$.nationality"}},
						{Name: "Member State of Application", Path: []string{"$.decision_legislation_applicable.member_state_which_legislation_applies"}},
					},
				},
			},
		},
	}
}

func pid() *openid4vp.PresentationDefinition {
	pidVCTs := []string{
		"https://vc-interop-3.sunet.se/credential/pid/1.0",
		"https://vc-interop-1.sunet.se/credential/pid/1.0",
		"https://satosa-test-1.sunet.se/credential/pid/1.0",
		"https://satosa-dev-1.sunet.se/credential/pid/1.0",
		"urn:credential:vid",
		"urn:credential:pid",
		"urn:eudi:pid:1",
		"PIDCredential",
		"PID"}

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
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: pidVCTs}},
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

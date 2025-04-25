package apiv1

import "vc/pkg/openid4vp"

func EHICPresentationDefinition() *openid4vp.PresentationDefinition {
	ehicVCTs := []string{
		"https://vc-interop-1.sunet.se/credential/ehic/1.0",
		"https://satosa-test-1.sunet.se/credential/ehic/1.0",
		"https://satosa-dev-1.sunet.se/credential/ehic/1.0",
		"EHICCredential"}
	return &openid4vp.PresentationDefinition{
		ID:          "SatosaEuropeanHealthInsuranceCard",
		Title:       "SATOSA EHIC",
		Description: "Required Fields: VC type, SSN, Forename, Family Name, Birthdate",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "SatosaEHIC",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
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

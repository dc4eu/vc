package apiv1

import "vc/pkg/openid4vp"

func PDA1PresentationDefinition() *openid4vp.PresentationDefinition {
	pda1VCTs := []string{
		"https://vc-interop-1.sunet.se/credential/pda1/1.0",
		"https://satosa-test-1.sunet.se/credential/pda1/1.0",
		"https://satosa-dev-1.sunet.se/credential/pda1/1.0",
		"PDA1Credential"}
	return &openid4vp.PresentationDefinition{
		ID:          "SatosaPDA1",
		Title:       "SATOSA PDA1",
		Description: "Required Fields: VC type, SSN, Member State of Application",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "SatosaPDA1",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
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

package apiv1

import "vc/pkg/openid4vp"

func DiplomaPresentationDefinition() *openid4vp.PresentationDefinition {
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
		Format: map[string]openid4vp.Format{
			"vc+sd-jwt": {Alg: []string{"ES256"}},
		},
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "Bachelor",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
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
	return nil
}

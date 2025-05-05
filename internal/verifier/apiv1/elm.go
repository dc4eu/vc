package apiv1

import "vc/pkg/openid4vp"

func ELMPresentationDefinition() *openid4vp.PresentationDefinition {
	vctList := []string{
		"https://vc-interop-3.sunet.se/credential/elm/1.0",
		"https://vc-interop-1.sunet.se/credential/elm/1.0",
		"https://satosa-test-1.sunet.se/credential/elm/1.0",
		"https://satosa-dev-1.sunet.se/credential/elm/1.0",
		"urn:credential:elm",
		"ELMCredential",
		"ElmCredential",
		"ELM"}
	return &openid4vp.PresentationDefinition{
		ID:          "ELM",
		Title:       "European Learning Model for EMREX",
		Description: "Required Fields: VC type, ELM",
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "ELM",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
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

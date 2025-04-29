package apiv1

import "vc/pkg/openid4vp"

func PIDPresentationDefinition() *openid4vp.PresentationDefinition {
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
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "PID",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
				Constraints: openid4vp.Constraints{
					Fields: []openid4vp.Field{
						{Name: "VC type", Path: []string{"$.vct"}, Filter: openid4vp.Filter{Type: "string", Enum: pidVCTs}},
						{Name: "Given Name", Path: []string{"$.subject.given_name"}},
						{Name: "Family Name", Path: []string{"$.subject.family_name"}},
						{Name: "Birth Date", Path: []string{"$.subject.birthdate"}},
					},
				},
			},
		},
	}
}

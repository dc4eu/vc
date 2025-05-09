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
		Selectable:  true, // special field found i db4eu verifier
		Format: map[string]openid4vp.Format{
			"vc+sd-jwt": {Alg: []string{"ES256"}},
		},
		InputDescriptors: []openid4vp.InputDescriptor{
			{
				ID: "PID",
				Format: map[string]openid4vp.Format{
					"vc+sd-jwt": {Alg: []string{"ES256"}},
				},
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

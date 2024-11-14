package apiv1

import "fmt"

func (c *ehicClient) MetadataClaim(vct string) ([]string, error) {
	var (
		socialSecurityPin    = "social_security_pin"
		competentInstitution = "competent_institution"
		institutionCountry   = "institution_country"
		institutionID        = "institution_id"
		documentID           = "document_id"
		periodEntitlement    = "period_entitlement"
		endingDate           = "ending_date"
	)

	vctm := VCTM{
		VCT:         vct,
		Name:        "EHIC",
		Description: "This is an EHIC document issued by the well known EHIC Issuer",
		Display: []VCTMDisplay{
			{
				Lang: "en-US",
				Name: "EHIC",
				Rendering: Rendering{
					Simple: SimpleRendering{
						Logo: Logo{
							URI:          fmt.Sprintf("%s/ehicCard.png", c.client.cfg.Issuer.JWTAttribute.Issuer),
							URIIntegrity: "sha256-94445b2ca72e9155260c8b4879112df7677e8b3df3dcee9b970b40534e26d4ab",
							AltText:      "EHIC Card",
						},
						BackgroundColor: "#12107c",
						TextColor:       "#FFFFFF",
					},
					SVGTemplates: []SVGTemplates{
						{
							URI:          fmt.Sprintf("%s/ehicTemplate.png", c.client.cfg.Issuer.JWTAttribute.Issuer),
							URLIntegrity: "",
							Properties:   SVGTemplateProperties{},
						},
					},
				},
			},
		},
		Claims: []Claim{
			{
				Path: []*string{&socialSecurityPin},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "Social Security Number",
						Description: "The social security number of the EHIC holder",
					},
				},
				SD:    "",
				SVGID: "social_security_pin",
			},
			{
				Path: []*string{&competentInstitution, &institutionCountry},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "Issuer Country",
						Description: "The issuer country of the EHIC holder",
					},
				},
				SD:    "",
				SVGID: "issuer_country",
			},
			{
				Path: []*string{&competentInstitution, &institutionID},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "Issuer Institution Code",
						Description: "The issuer institution code of the EHIC holder",
					},
				},
				SD:    "",
				SVGID: "issuer_institution_code",
			},
			{
				Path: []*string{&documentID},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "Identification card number",
						Description: "The Identification card number of the EHIC holder",
					},
				},
				SD:    "",
				SVGID: "identification_number_card",
			},
			{
				Path: []*string{&periodEntitlement, &endingDate},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "Expiry Date",
						Description: "The date and time expired this credential",
					},
				},
				SD:    "",
				SVGID: "expiry_date",
			},
		},
		SchemaURL:          "",
		SchemaURLIntegrity: "",
		Extends:            "",
		ExtendsIntegrity:   "",
	}

	e, err := vctm.encode()
	if err != nil {
		return nil, err
	}
	return []string{e}, nil
}

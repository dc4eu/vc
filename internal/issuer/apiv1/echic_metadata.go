package apiv1

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
							URI:          "https://raw.githubusercontent.com/dc4eu/vc/9832bb494ecd982c3aa56ed1b504e3a884d46d23/images/ehiccard.png",
							URIIntegrity: "sha256-124c5fea148d56527baa77259942b6ee5050e635cc86c268fd42587d022a69c7",
							AltText:      "EHIC Card",
						},
						BackgroundColor: "#12107c",
						TextColor:       "#FFFFFF",
					},
					SVGTemplates: []SVGTemplates{
						{
							URI:          "https://raw.githubusercontent.com/dc4eu/vc/9832bb494ecd982c3aa56ed1b504e3a884d46d23/images/ehicTemplate.svg",
							URLIntegrity: "sha256-c9089cb2c8b845a69978cc9adc2d53c88207ed5a586399b9aede8e1a93cd305a",
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

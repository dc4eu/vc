package apiv1

func (c *elmClient) MetadataClaim(vct string) ([]string, error) {
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
		Name:        "ELM",
		Description: "This is an ELM document issued by the well known ELM Issuer",
		Display: []VCTMDisplay{
			{
				Lang: "en-US",
				Name: "ELM",
				Rendering: Rendering{
					SVGTemplates: []SVGTemplates{
						{
							URI:          "https://raw.githubusercontent.com/dc4eu/vc/633940b0b00ab259af01cfbff958f1ffebf5176a/images/diplomaTemplate.svg",
							URLIntegrity: "sha256-1acd4883826aba0318d219213bb75a9dfc858f926e93f576224412301fe3018a",
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

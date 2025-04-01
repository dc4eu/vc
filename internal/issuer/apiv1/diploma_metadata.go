package apiv1

func (c *diplomaClient) MetadataClaim(vct string) ([]string, error) {
	var (
	//	socialSecurityPin    = "social_security_pin"
	//	competentInstitution = "competent_institution"
	//	institutionCountry   = "institution_country"
	//	institutionID        = "institution_id"
	//	documentID           = "document_id"
	//	periodEntitlement    = "period_entitlement"
	//	endingDate           = "ending_date"
	)

	vctm := VCTM{
		VCT:         vct,
		Name:        "Diploma",
		Description: "This is an Diploma document issued by the well known Diploma Issuer",
		Display: []VCTMDisplay{
			{
				Lang: "en-US",
				Name: "Diploma",
				Rendering: Rendering{
					SVGTemplates: []SVGTemplates{
						{
							URI:          "https://raw.githubusercontent.com/dc4eu/vc/9832bb494ecd982c3aa56ed1b504e3a884d46d23/images/diplomaTemplate.svg",
							URLIntegrity: "sha256-20ca202ae2b3103b967d64483dee45ed10494e6de9f009b04e521a3a8e14d79d",
							Properties:   SVGTemplateProperties{},
						},
					},
				},
			},
		},
		Claims:             []Claim{},
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

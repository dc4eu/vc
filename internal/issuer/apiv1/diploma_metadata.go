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

							URI:          "https://raw.githubusercontent.com/dc4eu/vc/633940b0b00ab259af01cfbff958f1ffebf5176a/images/diplomaTemplate.svg",
							URLIntegrity: "sha256-1acd4883826aba0318d219213bb75a9dfc858f926e93f576224412301fe3018a",
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

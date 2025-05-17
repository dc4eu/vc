package apiv1

func (c *pidClient) MetadataClaim(vct string) ([]string, error) {
	var (
		claimFirstName   = "first_name"
		claimFamilyName  = "family_name"
		claimDateOfBirth = "date_of_birth"
	)
	vctm := VCTM{
		VCT:         vct,
		Name:        "PID",
		Description: "This is a PID document issued by the well known PID Issuer",
		Display: []VCTMDisplay{
			{
				Lang:        "en-US",
				Name:        "PID",
				Description: "",
				Rendering: Rendering{
					SVGTemplates: []SVGTemplates{
						{
							URI:          "https://raw.githubusercontent.com/SUNET/openid4v/9af381e628cb88abe79e8a17572a165a449dcdf2/images/template-pid.svg",
							URLIntegrity: "sha256-0def174036c9fbdc849db8c617a94e7ed574c31012e1a7157616d8f5faa79ba8",
							Properties:   SVGTemplateProperties{},
						},
					},
				},
			},
		},
		Claims: []Claim{
			{
				Path: []*string{&claimFirstName},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "PID fist name",
						Description: "The first name of the PID holder",
					},
				},
				SD:    "always",
				SVGID: "first_name",
			},
			{
				Path: []*string{&claimFamilyName},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "PID family name",
						Description: "The family name of the PID holder",
					},
				},
				SD:    "always",
				SVGID: "family_name",
			},
			{
				Path: []*string{&claimDateOfBirth},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "PID date of birth",
						Description: "The date of birth of the PID holder",
					},
				},
				SD:    "always",
				SVGID: "date_of_birth",
			},
		},
		SchemaURL:          "",
		SchemaURLIntegrity: "",
		Extends:            "",
		ExtendsIntegrity:   "",
	}

	encoded, err := vctm.encode()
	if err != nil {
		return nil, err
	}

	return []string{encoded}, nil
}

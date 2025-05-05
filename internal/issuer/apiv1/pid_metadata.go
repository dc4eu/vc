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
					Simple: SimpleRendering{
						Logo: Logo{
							URI:          "https://raw.githubusercontent.com/dc4eu/vc/9832bb494ecd982c3aa56ed1b504e3a884d46d23/images/pda1.png",
							URIIntegrity: "sha256-ecf6af03924f152deb2fad59c8496750a12e376a3b2b575d53b79f22241e3d96",
							AltText:      "PDA1 Card",
						},
						BackgroundColor: "#8ebeeb",
						TextColor:       "#ffffff",
					},
					SVGTemplates: []SVGTemplates{
						{
							URI:          "https://raw.githubusercontent.com/dc4eu/vc/9832bb494ecd982c3aa56ed1b504e3a884d46d23/images/pda1Template.svg",
							URLIntegrity: "sha256-35a9eecb4d2d8d92e42a33e7e765afc6b24c8875cf145ea1b29cde9cd2f63f5e",
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

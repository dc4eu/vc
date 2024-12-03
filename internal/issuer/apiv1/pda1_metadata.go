package apiv1

//"vctm": {
//	"vct": <pda1_vct>,
//	"name": "PDA1",
//	"description": "This is a PDA1 document issued by the well known PDA1 Issuer",
//	"display": [
//		{
//			"en-US": {
//				"name": "PDA1",
//				"rendering": {
//					"simple": {
//						"logo": {
//							"uri": "<your_domain>/pda1.png",
//							"uri#integrity": "sha256-94445b2ca72e9155260c8b4879112df7677e8b3df3dcee9b970b40534e26d4ab",
//							"alt_text": "PDA1 Card"
//						},
//						"backgroundColor": "#8ebeeb",
//						"textColor": "#ffffff"
//					},
//					"svg_templates": [
//						{
//							"uri": "<your_domain>/pda1Template.svg"
//						}
//					]
//				}
//			}
//		}
//	],
//	"claims": [
//		{
//			"path": [
//				"social_security_pin"
//			],
//			"display": {
//				"en-US": {
//					"label": "Social Security Number",
//					"description": "The social security number of the PDA1 holder"
//				}
//			},
//			"svg_id": "social_security_pin"
//		},
//		{
//			"path": [
//				"decision_legislation_applicable", "ending_date"
//			],
//			"display": {
//				"en-US": {
//					"label": "Expiry Date",
//					"description": "The date and time expired this credential"
//				}
//			},
//			"svg_id": "expiry_date"
//		}
//	]
//}

func (c *pda1Client) MetadataClaim(vct string) ([]string, error) {
	var (
		socialSecurityPin             = "social_security_pin"
		decisionLegislationApplicable = "decision_legislation_applicable"
		endingDate                    = "ending_date"
	)
	vctm := VCTM{
		VCT:         vct,
		Name:        "PDA1",
		Description: "This is a PDA1 document issued by the well known PDA1 Issuer",
		Display: []VCTMDisplay{
			{
				Lang:        "en-US",
				Name:        "PDA1",
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
				Path: []*string{&socialSecurityPin},
				Display: []ClaimDisplay{
					{
						Lang:        "en-US",
						Label:       "Social Security Number",
						Description: "The social security number of the PDA1 holder",
					},
				},
				SD:    "",
				SVGID: "social_security_pin",
			},
			{
				Path: []*string{&decisionLegislationApplicable, &endingDate},
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

	encoded, err := vctm.encode()
	if err != nil {
		return nil, err
	}

	return []string{encoded}, nil
}

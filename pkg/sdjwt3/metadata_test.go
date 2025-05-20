package sdjwt3

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

func TestMetadata(t *testing.T) {
	var (
		degreesPrt    = "degrees"
		namePrt       = "name"
		addressPrt    = "address"
		streetAddress = "street_address"
	)
	tts := []struct {
		name string
		have VCTM
	}{
		{
			name: "test",
			have: VCTM{
				VCT:              "https://betelgeuse.example.com/education_credential",
				Name:             "Betelgeuse Education Credential - Preliminary Version",
				Description:      "This is our development version of the education credential. Don't panic.",
				Extends:          "https://galaxy.example.com/galactic-education-credential-0.9",
				ExtendsIntegrity: "sha256-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-WRL5",
				Display: []VCTMDisplay{
					{
						Lang:        "en-US",
						Name:        "Betelgeuse Education Credential",
						Description: "An education credential for all carbon-based life forms on Betelgeusians",
						Rendering: Rendering{
							Simple: SimpleRendering{
								Logo: Logo{
									URI:          "https://betelgeuse.example.com/public/education-logo.png",
									URIIntegrity: "sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V",
									AltText:      "Betelgeuse Ministry of Education logo",
								},
								BackgroundColor: "#12107c",
								TextColor:       "#FFFFFF",
							},
							SVGTemplates: []SVGTemplates{
								{
									URI:          "https://betelgeuse.example.com/public/credential-english.svg",
									URLIntegrity: "sha256-8cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-9c",
									Properties: SVGTemplateProperties{
										Orientation: "landscape",
										ColorScheme: "light",
										Contrast:    "high",
									},
								},
							},
						},
					},
					{
						Lang: "de-DE",
						Name: "Betelgeuse-Bildungsnachweis",
						Rendering: Rendering{
							Simple: SimpleRendering{
								Logo: Logo{
									URI:          "https://betelgeuse.example.com/public/education-logo-de.png",
									URIIntegrity: "sha256-LmXfh-9cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1V",
									AltText:      "Logo des Betelgeusischen Bildungsministeriums",
								},
								BackgroundColor: "#12107c",
								TextColor:       "#FFFFFF",
							},
							SVGTemplates: []SVGTemplates{
								{
									URI:          "https://betelgeuse.example.com/public/credential-german.svg",
									URLIntegrity: "sha256-8cLlJNXN-TsMk-PmKjZ5t0WRL5ca_xGgX3c1VLmXfh-9c",
									Properties: SVGTemplateProperties{
										Orientation: "landscape",
										ColorScheme: "light",
										Contrast:    "high",
									},
								},
							},
						},
					},
				},
				Claims: []Claim{
					{
						Path: []*string{&namePrt},
						Display: []ClaimDisplay{
							{
								Lang:        "de-DE",
								Label:       "Vor- und Nachname",
								Description: "Der Name des Studenten",
							},
							{
								Lang:        "en-US",
								Label:       "Name",
								Description: "The name of the student",
							},
						},
						SD: "allowed",
					},
					{
						Path: []*string{&addressPrt},
						Display: []ClaimDisplay{
							{
								Lang:        "de-DE",
								Label:       "Adresse",
								Description: "Adresse zum Zeitpunkt des Abschlusses",
							},
							{
								Lang:        "en-US",
								Label:       "Address",
								Description: "Address at the time of graduation",
							},
						},
						SD: "always",
					},
					{
						Path: []*string{&addressPrt, &streetAddress},
						Display: []ClaimDisplay{
							{
								Lang:  "de-DE",
								Label: "Straße",
							},
							{
								Lang:  "en-US",
								Label: "Street Address",
							},
						},
						SD:    "always",
						SVGID: "address_street_address",
					},
					{
						Path: []*string{&degreesPrt, nil},
						Display: []ClaimDisplay{
							{
								Lang:        "de-DE",
								Label:       "Abschluss",
								Description: "Der Abschluss des Studenten",
							},
							{
								Lang:        "en-US",
								Label:       "Degree",
								Description: "Degree earned by the student",
							},
						},
						SD: "allowed",
					},
				},
				SchemaURL:          "https://exampleuniversity.com/public/credential-schema-0.9",
				SchemaURLIntegrity: "sha256-o984vn819a48ui1llkwPmKjZ5t0WRL5ca_xGgX3c1VLmXfh",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			want := golden.Get(t, "vtcm.golden")

			got, err := json.Marshal(tt.have)
			assert.NoError(t, err)

			assert.JSONEq(t, string(want), string(got))

		})
	}

}

package apiv1

// VCTM is the VCTM
type VCTM struct {
	VCT                string        `json:"vct"`
	Name               string        `json:"name"`
	Description        string        `json:"description"`
	Display            []VCTMDisplay `json:"display"`
	Claims             []Claim       `json:"claims"`
	SchemaURL          string        `json:"schema_url"`
	SchemaURLIntegrity string        `json:"schema_url#integrity"`
	Extends            string        `json:"extends"`
	ExtendsIntegrity   string        `json:"extends#integrity"`
}

// VCTMDisplay is the display of the VCTM
type VCTMDisplay struct {
	Lang        string    `json:"lang"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Rendering   Rendering `json:"rendering"`
}

// Rendering is the rendering of the VCTM
type Rendering struct {
	Simple       SimpleRendering `json:"simple"`
	SVGTemplates []SVGTemplates  `json:"svg_templates"`
}

// SimpleRendering is the logo for the VCTM
type SimpleRendering struct {
	Logo            Logo   `json:"logo"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
}

// Logo is the logo for the VCTM
type Logo struct {
	URI          string `json:"uri"`
	URIIntegrity string `json:"uri#integrity"`
	AltText      string `json:"alt_text"`
}

// SVGTemplates is the SVGTemplates
type SVGTemplates struct {
	URI          string                `json:"uri"`
	URLIntegrity string                `json:"uri#integrity"`
	Properties   SVGTemplateProperties `json:"properties"`
}

// SVGTemplateProperties is the properties of the SVGTemplates
type SVGTemplateProperties struct {
	Orientation string `json:"orientation"`
	ColorScheme string `json:"color_scheme"`
	Contrast    string `json:"contrast"`
}

// Claim is the claims
type Claim struct {
	Path    []*string      `json:"path"`
	Display []ClaimDisplay `json:"display"`
	SD      string         `json:"sd"`
	SVGID   string         `json:"svg_id,omitempty"`
}

// ClaimDisplay is the display of the claims
type ClaimDisplay struct {
	Lang        string `json:"lang"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

func (c *Client) metadata() error {
	return nil
}

//"vctm": {
//	"vct": <ehic_vct>,
//	"name": "EHIC",
//	"description": "This is an EHIC document issued by the well known EHIC Issuer",
//	"display": [
//		{
//			"en-US": {
//				"name": "EHIC",
//				"rendering": {
//					"simple": {
//						"logo": {
//							"uri": "<your_domain>/ehicCard.png",
//							"uri#integrity": "sha256-94445b2ca72e9155260c8b4879112df7677e8b3df3dcee9b970b40534e26d4ab",
//							"alt_text": "EHIC Card"
//						},
//						"background_color": "#12107c",
//						"text_color": "#FFFFFF"
//					},
//					"svg_templates": [
//						{
//							"uri": "<your_domain>/ehicTemplate.svg"
//						}
//					]
//				}
//			}
//		}
//	]
//}

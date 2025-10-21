package openid4vci

import (
	"github.com/go-playground/validator/v10"
)

type VCTM struct {
	VCT                string        `json:"vct" bson:"vct" validate:"required"`
	Name               string        `json:"name" bson:"name" validate:"required"`
	Description        string        `json:"description" bson:"description" validate:"required"`
	Comment            string        `json:"$comment,omitempty" bson:"comment,omitempty"`
	Display            []VCTMDisplay `json:"display,omitempty" bson:"display,omitempty" validate:"omitempty,dive"`
	Claims             []VCTMClaim   `json:"claims,omitempty" bson:"claims,omitempty" validate:"omitempty,dive"`
	SchemaURI          string        `json:"schema_uri,omitempty" bson:"schema_uri,omitempty" validate:"omitempty,url"`
	SchemaURIIntegrity string        `json:"schema_uri#integrity,omitempty" bson:"schema_uri_integrity,omitempty" validate:"omitempty"`
}

type VCTMDisplay struct {
	Lang        string                `json:"lang,omitempty" bson:"lang,omitempty" validate:"omitempty,bcp47_language_tag"`
	Name        string                `json:"name" bson:"name" validate:"required"`
	Description string                `json:"description" bson:"description" validate:"required"`
	Rendering   *VCTMDisplayRendering `json:"rendering,omitempty" bson:"rendering,omitempty" validate:"omitempty"`
}

type VCTMDisplayRendering struct {
	SVGTemplates []VCTMDisplayRenderingSVGTemplate `json:"svg_templates,omitempty" bson:"svg_templates,omitempty" validate:"omitempty,dive"`
}

type VCTMDisplayRenderingSVGTemplate struct {
	URI          string                 `json:"uri" bson:"uri" validate:"required,url"`
	URIIntegrity string                 `json:"uri#integrity,omitempty" bson:"uri_integrity,omitempty" validate:"omitempty"`
	Properties   *VCTMDisplayProperties `json:"properties,omitempty" bson:"properties,omitempty" validate:"omitempty"`
}

type VCTMDisplayProperties struct {
	Orientation string `json:"orientation,omitempty" bson:"orientation,omitempty" validate:"omitempty,oneof=landscape portrait"`
	ColorScheme string `json:"color_scheme,omitempty" bson:"color_scheme,omitempty" validate:"omitempty,oneof=light dark"`
	Contrast    string `json:"contrast,omitempty" bson:"contrast,omitempty" validate:"omitempty,oneof=normal high"`
}

type VCTMClaim struct {
	Path    []string           `json:"path" bson:"path" validate:"required,min=1,dive,required"`
	SD      string             `json:"sd" bson:"sd,omitempty" validate:"required,oneof=always never" `
	SVGID   string             `json:"svg_id,omitempty" bson:"svg_id,omitempty" validate:"omitempty"`
	Display []VCTMClaimDisplay `json:"display,omitempty" bson:"display,omitempty" validate:"omitempty,dive"`
}

type VCTMClaimDisplay struct {
	Lang        string `json:"lang,omitempty" bson:"lang,omitempty" validate:"omitempty,bcp47_language_tag"`
	Label       string `json:"label" bson:"label" validate:"required"`
	Description string `json:"description" bson:"description" validate:"required"`
}

func (v *VCTM) Validate() error {
	validator := validator.New()
	return validator.Struct(v)
}

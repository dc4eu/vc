package openid4vp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
)

type AuthorizationResponse struct {
	IDToken                string                  `json:"id_token,omitempty"`                //JWT
	VPTokens               []VPTokenRaw            `json:"vp_token,omitempty"`                //JWT or JSON
	PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty"` //JSON
	State                  string                  `json:"state,omitempty"`                   //Must exist if existed in AuthorizationRequest
	Error                  string                  `json:"error,omitempty"`                   //Must exist if error occured on the holder side
	ErrorDescription       string                  `json:"error_description,omitempty"`       //Optional on error
	ErrorURI               string                  `json:"error_uri,omitempty"`               //Optional on error
}

func (v *AuthorizationResponse) UnmarshalJSON(data []byte) error {
	// no recursion
	type Alias AuthorizationResponse
	aux := struct {
		IDToken                string                  `json:"id_token,omitempty"`
		VPTokens               json.RawMessage         `json:"vp_token,omitempty"`
		PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty"`
		State                  string                  `json:"state,omitempty"`
		Error                  string                  `json:"error,omitempty"`
		ErrorDescription       string                  `json:"error_description,omitempty"`
		ErrorURI               string                  `json:"error_uri,omitempty"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	v.PresentationSubmission = aux.PresentationSubmission
	v.State = aux.State
	v.Error = aux.Error
	v.ErrorDescription = aux.ErrorDescription
	v.ErrorURI = aux.ErrorURI

	if len(aux.VPTokens) == 0 || string(aux.VPTokens) == "null" {
		// vp_token is missing or nil
		v.VPTokens = nil
		return nil
	}

	// array?
	var rawList []json.RawMessage
	if err := json.Unmarshal(aux.VPTokens, &rawList); err == nil {
		for _, item := range rawList {
			var token VPTokenRaw
			if isString(item) {
				if err := json.Unmarshal(item, &token.JWT); err != nil {
					return err
				}
			} else {
				if err := json.Unmarshal(item, &token.JSON); err != nil {
					return err
				}
			}
			v.VPTokens = append(v.VPTokens, token)
		}
		return nil
	}

	// not array – try as single value
	var singleStr string
	if err := json.Unmarshal(aux.VPTokens, &singleStr); err == nil {
		v.VPTokens = []VPTokenRaw{{JWT: singleStr}}
		return nil
	}
	var singleObj map[string]interface{}
	if err := json.Unmarshal(aux.VPTokens, &singleObj); err == nil {
		v.VPTokens = []VPTokenRaw{{JSON: singleObj}}
		return nil
	}

	return fmt.Errorf("vp_token is neither string, object, nor array")
}

func isString(msg json.RawMessage) bool {
	return len(msg) > 0 && msg[0] == '"'
}

type VPTokenRaw struct {
	JWT  string                 `json:"jwt,omitempty"`
	JSON map[string]interface{} `json:"json,omitempty"`
}

func (vp *VPTokenRaw) isJWTBased() bool {
	return vp.JWT != ""
}

func (vp *VPTokenRaw) isJSONBased() bool {
	return vp.JSON != nil
}

//
//func (vp *VPTokenRaw) UnmarshalJSON(data []byte) error {
//	var jwt string
//	if err := json.Unmarshal(data, &jwt); err == nil {
//		vp.JWT = jwt
//		return nil
//	}
//
//	var jsonObj map[string]interface{}
//	if err := json.Unmarshal(data, &jsonObj); err == nil {
//		vp.JSON = jsonObj
//		return nil
//	}
//
//	return fmt.Errorf("vp_token has unknown format in UnmarshalJSON: %s", string(data))
//}

func ToVPTokenRaw(data []byte) (*VPTokenRaw, error) {
	var jwt string
	if err := json.Unmarshal(data, &jwt); err == nil {
		return &VPTokenRaw{JWT: jwt}, nil
	}

	var jsonObj map[string]interface{}
	if err := json.Unmarshal(data, &jsonObj); err == nil {
		return &VPTokenRaw{JSON: jsonObj}, nil
	}

	raw := string(data)
	if looksLikeJWT(raw) {
		return &VPTokenRaw{JWT: raw}, nil
	}

	return nil, fmt.Errorf("vp_token has unknown format in ToVPTokenRaw: %s", string(data))
}

func looksLikeJWT(s string) bool {
	parts := strings.Split(s, ".")
	return len(parts) == 3 || len(parts) == 5
}

// === Below: generated based on differens schemas and examples

type PresentationDefinition struct {
	ID                     string                  `json:"id"`
	Title                  string                  `json:"title,omitempty"`
	Description            string                  `json:"description,omitempty"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
	Selectable             bool                    `json:"_selectable,omitempty"`
	Format                 map[string]Format       `json:"format,omitempty"`
}

type InputDescriptor struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Purpose     string            `json:"purpose,omitempty"`
	Format      map[string]Format `json:"format,omitempty"`
	Group       []string          `json:"group,omitempty"`
	Constraints Constraints       `json:"constraints"`
}

type Format struct {
	Alg []string `json:"alg"`
}

type Constraints struct {
	LimitDisclosure string  `json:"limit_disclosure,omitempty"`
	Fields          []Field `json:"fields,omitempty"`
}

type Field struct {
	Name   string   `json:"name,omitempty"`
	Path   []string `json:"path"`
	Filter Filter   `json:"filter,omitempty"`
}

type Filter struct {
	Type string   `json:"type,omitempty"`
	Enum []string `json:"enum,omitempty"`
}

type SubmissionRequirement struct {
	Name  string `json:"name,omitempty"`
	Rule  string `json:"rule"`
	Count int    `json:"count,omitempty"`
	From  string `json:"from"`
}

func (sr SubmissionRequirement) Validate() error {
	if sr.Rule != "pick" {
		return errors.New("invalid rule, only 'pick' is allowed")
	}
	if sr.From == "" {
		return errors.New("'from' field is required")
	}
	return nil
}

type PresentationDefinitionEnvelope struct {
	PresentationDefinition PresentationDefinition `json:"presentation_definition" validate:"required"`
}

// ToJSON converts the struct into a JSON string
func (pde *PresentationDefinitionEnvelope) ToJSON() (string, error) {
	data, err := json.MarshalIndent(pde, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Example usage
func ExamplePresentationDefinition() error {
	pde := PresentationDefinitionEnvelope{
		PresentationDefinition: PresentationDefinition{
			ID:          "SatosaEuropeanHealthInsuranceCard",
			Title:       "SATOSA EHIC",
			Description: "Required Fields: VC type, SSN, Forename, Family Name, Birthdate",
			InputDescriptors: []InputDescriptor{
				{
					ID: "SatosaEHIC",
					Format: map[string]Format{
						"vc+sd-jwt": {Alg: []string{"ES256"}},
					},
					Constraints: Constraints{
						Fields: []Field{
							{Name: "VC type", Path: []string{"$.vct"}, Filter: Filter{Type: "string", Enum: []string{"https://vc-interop-1.sunet.se/credential/ehic/1.0", "https://satosa-test-1.sunet.se/credential/ehic/1.0", "https://satosa-dev-1.sunet.se/credential/ehic/1.0", "EHICCredential"}}},
							{Name: "SSN", Path: []string{"$.social_security_pin"}},
							{Name: "Forename", Path: []string{"$.subject.forename"}},
							{Name: "Family Name", Path: []string{"$.subject.family_name"}},
							{Name: "Birthdate", Path: []string{"$.subject.date_of_birth"}},
							{Name: "Document ID", Path: []string{"$.document_id"}},
							{Name: "Competent Institution", Path: []string{"$.competent_institution.institution_name"}},
						},
					},
				},
			},
		},
	}

	jsonData, err := pde.ToJSON()
	if err != nil {
		return err
	}
	fmt.Println(string(jsonData))
	return nil
}

//======================================== PRESENTATION SUBMISSION START ========================================

type Descriptor struct {
	ID         string      `json:"id" validate:"required"`
	Path       string      `json:"path" validate:"required"`
	PathNested *Descriptor `json:"path_nested,omitempty"`
	Format     string      `json:"format" validate:"required,oneof=jwt jwt_vc jwt_vp ldp ldp_vc ldp_vp mso_mdoc ac_vc ac_vp sd_jwt"`
}

type PresentationSubmission struct {
	ID            string       `json:"id" validate:"required"`
	DefinitionID  string       `json:"definition_id" validate:"required"`
	DescriptorMap []Descriptor `json:"descriptor_map" validate:"required,dive,required"`
}

type PresentationSubmissionEnvelope struct {
	PresentationSubmission PresentationSubmission `json:"presentation_submission" validate:"required"`
}

type SubmissionRequirementsEnvelope struct {
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements" validate:"required,dive,required"`
}

// ToJSON converts the struct into a JSON string
func (pse *PresentationSubmissionEnvelope) ToJSON() (string, error) {
	data, err := json.MarshalIndent(pse, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Example usage
func ExamplePresentationSubmission() {
	exampleJSON := `{
		"presentation_submission": {
		"id": "submission-123",
		"definition_id": "def-456",
		"descriptor_map": [
		  {
			"id": "desc-1",
			"path": "$.verifiableCredential[0]",
			"format": "jwt_vc"
		  },
		  {
			"id": "desc-2",
			"path": "$.verifiablePresentation",
			"format": "ldp_vp",
			"path_nested": {
			  "id": "desc-nested-1",
			  "path": "$.nestedField",
			  "format": "sd_jwt"
			}
		  }
		]
		}
	}`

	pse, err := FromJSON[PresentationSubmissionEnvelope](exampleJSON)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	//TODO: impl validate?

	jsonOutput, err := pse.ToJSON()
	if err != nil {
		log.Fatalf("Error converting to JSON: %v", err)
	}

	fmt.Println("JSON Output:")
	fmt.Println(jsonOutput)
}

//======================================== GENERIC ==================================================

func FromJSON[T any](jsonData string) (*T, error) {
	var obj T
	err := json.Unmarshal([]byte(jsonData), &obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

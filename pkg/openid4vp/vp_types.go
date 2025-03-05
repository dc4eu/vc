package openid4vp

import (
	"encoding/json"
	"fmt"
	"log"
)

// TODO: flytta nedan struct till generic_types
type AuthorizationResponse struct {
	IDToken                string                  `json:"id_token,omitempty"`                //JWT
	VPTokens               []VPTokenRaw            `json:"vp_token,omitempty"`                //JWT or JSON
	PresentationSubmission *PresentationSubmission `json:"presentation_submission,omitempty"` //JSON
	State                  string                  `json:"state,omitempty"`                   //Must exist if existed in AuthorizationRequest
	Error                  string                  `json:"error,omitempty"`                   //Must exist if error occured on the holder side
	ErrorDescription       string                  `json:"error_description,omitempty"`       //Optional on error
	ErrorURI               string                  `json:"error_uri,omitempty"`               //Optional on error
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

func (vp *VPTokenRaw) UnmarshalJSON(data []byte) error {
	var jwt string
	if err := json.Unmarshal(data, &jwt); err == nil {
		vp.JWT = jwt
		return nil
	}

	var jsonObj map[string]interface{}
	if err := json.Unmarshal(data, &jsonObj); err == nil {
		vp.JSON = jsonObj
		return nil
	}

	return fmt.Errorf("vp_token has unknown format: %s", string(data))
}

// === Below: generated based on all schemas found under header https://identity.foundation/presentation-exchange/spec/v2.0.0/#json-schemas (oid4vp20 points to v2.0.0)

type StatusDirective struct {
	Directive string   `json:"directive" validate:"oneof=required allowed disallowed"`
	Type      []string `json:"type" validate:"min=1,dive,required"`
}

type Field struct {
	ID             string          `json:"id,omitempty"`
	Optional       bool            `json:"optional,omitempty"`
	Path           []string        `json:"path" validate:"required,dive,required"`
	Purpose        string          `json:"purpose,omitempty"`
	IntentToRetain bool            `json:"intent_to_retain,omitempty"`
	Name           string          `json:"name,omitempty"`
	Filter         json.RawMessage `json:"filter,omitempty"`
	Predicate      string          `json:"predicate,omitempty" validate:"omitempty,oneof=required preferred"`
}

type Constraints struct {
	LimitDisclosure string                     `json:"limit_disclosure,omitempty" validate:"omitempty,oneof=required preferred"`
	Statuses        map[string]StatusDirective `json:"statuses,omitempty"`
	Fields          []Field                    `json:"fields,omitempty"`
	SubjectIsIssuer string                     `json:"subject_is_issuer,omitempty" validate:"omitempty,oneof=required preferred"`
	IsHolder        []HolderDirective          `json:"is_holder,omitempty"`
	SameSubject     []HolderDirective          `json:"same_subject,omitempty"`
}

type HolderDirective struct {
	FieldID   []string `json:"field_id" validate:"required,dive,required"`
	Directive string   `json:"directive" validate:"oneof=required preferred"`
}

type ClaimFormatDesignations struct {
	JWT     *AlgorithmDefinition `json:"jwt,omitempty"`
	JWTVc   *AlgorithmDefinition `json:"jwt_vc,omitempty"`
	JWTVp   *AlgorithmDefinition `json:"jwt_vp,omitempty"`
	LDPVc   *ProofTypeDefinition `json:"ldp_vc,omitempty"`
	LDPVp   *ProofTypeDefinition `json:"ldp_vp,omitempty"`
	LDP     *ProofTypeDefinition `json:"ldp,omitempty"`
	ACVc    *ProofTypeDefinition `json:"ac_vc,omitempty"`
	ACVp    *ProofTypeDefinition `json:"ac_vp,omitempty"`
	MSOMdoc json.RawMessage      `json:"mso_mdoc,omitempty"`
	SDJWT   *AlgorithmDefinition `json:"sd_jwt,omitempty"`
	//TODO vc+sd-jwt har i senare specifikationer blivit ersatt av sd_jwt???
	VCSDJWT *AlgorithmDefinition `json:"vc+sd-jwt,omitempty"`
}

type AlgorithmDefinition struct {
	Alg []string `json:"alg" validate:"min=1,dive,required"`
}

type ProofTypeDefinition struct {
	ProofType []string `json:"proof_type" validate:"min=1,dive,required"`
}

type InputDescriptor struct {
	ID          string      `json:"id" validate:"required"`
	Name        string      `json:"name,omitempty"`
	Purpose     string      `json:"purpose,omitempty"`
	Group       []string    `json:"group,omitempty"`
	Constraints Constraints `json:"constraints" validate:"required"`
}

type SubmissionRequirement struct {
	Name       string                  `json:"name,omitempty"`
	Purpose    string                  `json:"purpose,omitempty"`
	Rule       string                  `json:"rule" validate:"oneof=all pick"`
	Count      *int                    `json:"count,omitempty" validate:"omitempty,min=1"`
	Min        *int                    `json:"min,omitempty" validate:"omitempty,min=0"`
	Max        *int                    `json:"max,omitempty" validate:"omitempty,min=0"`
	From       string                  `json:"from,omitempty"`
	FromNested []SubmissionRequirement `json:"from_nested,omitempty" validate:"omitempty,dive"`
}

type PresentationDefinition struct {
	ID                     string                  `json:"id" validate:"required"`
	Name                   string                  `json:"name,omitempty"`
	Purpose                string                  `json:"purpose,omitempty"`
	Format                 ClaimFormatDesignations `json:"format" validate:"required"`
	Frame                  map[string]interface{}  `json:"frame,omitempty"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,omitempty"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors" validate:"required,dive,required"`
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
func ExamplePresentationDefinition() {
	exampleJSON := `{
	  "presentation_definition": {
		"id": "12345",
		"name": "Example Presentation Definition",
		"purpose": "To verify credentials",
		"format": {
		  "jwt": {
			"alg": ["RS256", "ES256"]
		  },
		  "jwt_vc": {
			"alg": ["RS512"]
		  },
		  "jwt_vp": {
			"alg": ["ES384"]
		  },
		  "ldp_vc": {
			"proof_type": ["Ed25519Signature2018"]
		  },
		  "ldp_vp": {
			"proof_type": ["RsaSignature2018"]
		  },
		  "ldp": {
			"proof_type": ["BbsBlsSignature2020"]
		  },
		  "ac_vc": {
			"proof_type": ["CLSignature"]
		  },
		  "ac_vp": {
			"proof_type": ["CLSignature"]
		  },
		  "mso_mdoc": {},
		  "sd_jwt": {
			"alg": ["HS256"]
		  }
		},
		"frame": {
		  "example_frame_key": "example_value"
		},
		"submission_requirements": [
		  {
			"name": "SR1",
			"purpose": "Ensure specific claims are included",
			"rule": "all",
			"from": "groupA"
		  },
		  {
			"name": "SR2",
			"purpose": "Allow pick of some credentials",
			"rule": "pick",
			"min": 1,
			"max": 3,
			"from_nested": [
			  {
				"rule": "all",
				"from": "groupB"
			  }
			]
		  }
		],
		"input_descriptors": [
		  {
			"id": "input-1",
			"name": "Driver's License",
			"purpose": "Verify identity",
			"group": ["groupA"],
			"constraints": {
			  "limit_disclosure": "preferred",
			  "statuses": {
				"active": {
				  "directive": "required",
				  "type": ["active"]
				},
				"revoked": {
				  "directive": "disallowed",
				  "type": ["revoked"]
				}
			  },
			  "fields": [
				{
				  "id": "field-1",
				  "path": ["$.credentialSubject.id"],
				  "name": "Subject ID",
				  "purpose": "Unique identifier",
				  "optional": false,
				  "intent_to_retain": true,
				  "filter": {
					"type": "string",
					"pattern": "^[0-9a-fA-F]{24}$"
				  }
				},
				{
				  "id": "field-2",
				  "path": ["$.credentialSubject.age"],
				  "name": "Age",
				  "purpose": "Verify age",
				  "filter": {
					"type": "integer",
					"minimum": 18
				  },
				  "predicate": "required"
				}
			  ],
			  "subject_is_issuer": "preferred",
			  "is_holder": [
				{
				  "field_id": ["field-1"],
				  "directive": "required"
				}
			  ],
			  "same_subject": [
				{
				  "field_id": ["field-2"],
				  "directive": "preferred"
				}
			  ]
			}
		  }
		]
	  }
	}
	`

	pde, err := FromJSON[PresentationDefinitionEnvelope](exampleJSON)
	if err != nil {
		log.Fatalf("Error parsing JSON: %v", err)
	}

	//TODO: impl validate?

	jsonOutput, err := pde.ToJSON()
	if err != nil {
		log.Fatalf("Error converting to JSON: %v", err)
	}

	fmt.Println("JSON Output:")
	fmt.Println(jsonOutput)
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

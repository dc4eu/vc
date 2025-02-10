package openid4vp

import (
	"encoding/json"
	"fmt"
	"log"
)

//======================================== PRESENTATION DEFINITION START ========================================

//Generated from schema: https://identity.foundation/presentation-exchange/spec/v2.1.1/#presentation-definition-in-an-envelope

// StatusDirective represents the status directive schema.
type StatusDirective struct {
	Directive string   `json:"directive"`
	Type      []string `json:"type,minItems=1"`
}

// Field represents a field constraint.
type Field struct {
	ID             string          `json:"id,omitempty"`
	Optional       bool            `json:"optional,omitempty"`
	Path           []string        `json:"path,minItems=1"`
	Purpose        string          `json:"purpose,omitempty"`
	Name           string          `json:"name,omitempty"`
	IntentToRetain bool            `json:"intent_to_retain,omitempty"`
	Filter         json.RawMessage `json:"filter,omitempty"`
	Predicate      string          `json:"predicate,omitempty"`
}

// InputDescriptorFormat represents the allowed format types for InputDescriptor.
type InputDescriptorFormat struct {
	JWT     *AlgorithmConstraints `json:"jwt,omitempty"`
	JWTVc   *AlgorithmConstraints `json:"jwt_vc,omitempty"`
	JWTVp   *AlgorithmConstraints `json:"jwt_vp,omitempty"`
	LDPVc   *ProofConstraints     `json:"ldp_vc,omitempty"`
	LDPVp   *ProofConstraints     `json:"ldp_vp,omitempty"`
	LDP     *ProofConstraints     `json:"ldp,omitempty"`
	ACVc    *ProofConstraints     `json:"ac_vc,omitempty"`
	ACVp    *ProofConstraints     `json:"ac_vp,omitempty"`
	MSOMdoc *struct{}             `json:"mso_mdoc,omitempty"`
	SDJWT   *AlgorithmConstraints `json:"sd_jwt,omitempty"`
}

type AlgorithmConstraints struct {
	Alg []string `json:"alg,minItems=1"`
}

type ProofConstraints struct {
	ProofType []string `json:"proof_type,minItems=1"`
}

// InputDescriptor represents an input descriptor.
type InputDescriptor struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Format      *InputDescriptorFormat `json:"format,omitempty"`
	Group       []string               `json:"group,omitempty"`
	Constraints *Constraints           `json:"constraints"`
}

// Constraints represents input constraints.
type Constraints struct {
	LimitDisclosure string             `json:"limit_disclosure,omitempty"`
	Statuses        *StatusConstraints `json:"statuses,omitempty"`
	Fields          []Field            `json:"fields,minItems=1,omitempty"`
	SubjectIsIssuer string             `json:"subject_is_issuer,omitempty"`
	IsHolder        []HolderConstraint `json:"is_holder,minItems=1,omitempty"`
	SameSubject     []HolderConstraint `json:"same_subject,minItems=1,omitempty"`
}

// StatusConstraints represents status constraints.
type StatusConstraints struct {
	Active    *StatusDirective `json:"active,omitempty"`
	Suspended *StatusDirective `json:"suspended,omitempty"`
	Revoked   *StatusDirective `json:"revoked,omitempty"`
}

// HolderConstraint represents a holder constraint.
type HolderConstraint struct {
	FieldID   []string `json:"field_id,minItems=1"`
	Directive string   `json:"directive"`
}

// SubmissionRequirement represents submission requirement rules.
type SubmissionRequirement struct {
	Name       string                  `json:"name,omitempty"`
	Purpose    string                  `json:"purpose,omitempty"`
	Rule       string                  `json:"rule"`
	Count      int                     `json:"count,omitempty"`
	Min        int                     `json:"min,omitempty"`
	Max        int                     `json:"max,omitempty"`
	From       string                  `json:"from,omitempty"`
	FromNested []SubmissionRequirement `json:"from_nested,minItems=1,omitempty"`
}

// PresentationDefinition represents the main presentation definition.
type PresentationDefinition struct {
	ID                     string                  `json:"id"`
	Name                   string                  `json:"name,omitempty"`
	Purpose                string                  `json:"purpose,omitempty"`
	Format                 json.RawMessage         `json:"format,omitempty"`
	Frame                  map[string]interface{}  `json:"frame,omitempty"`
	SubmissionRequirements []SubmissionRequirement `json:"submission_requirements,minItems=1,omitempty"`
	InputDescriptors       []InputDescriptor       `json:"input_descriptors,minItems=1"`
}

// PresentationDefinitionEnvelope wraps the PresentationDefinition.
type PresentationDefinitionEnvelope struct {
	PresentationDefinition PresentationDefinition `json:"presentation_definition"`
}

// ToJSON converts the struct into a JSON string
func (pde *PresentationDefinitionEnvelope) ToJSON() (string, error) {
	data, err := json.MarshalIndent(pde, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FromJSON loads JSON data into a struct
func (pde *PresentationDefinitionEnvelope) FromJSON(jsonData string) (*PresentationDefinitionEnvelope, error) {
	var p PresentationDefinitionEnvelope
	err := json.Unmarshal([]byte(jsonData), &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Example usage
func ExamplePresentationDefinition() {
	exampleJSON := `{
	  "presentation_definition": {
		"id": "12345",
		"name": "Example Presentation Definition",
		"purpose": "To validate credentials",
		"format": {
		  "jwt": {
			"alg": ["ES256", "RS256"]
		  }
		},
		"frame": {
		  "type": "VerifiableCredential",
		  "credentialSubject": {
			"id": "did:example:123"
		  }
		},
		"submission_requirements": [
		  {
			"name": "Example Requirement",
			"purpose": "Ensure validity",
			"rule": "all",
			"from": "A"
		  }
		],
		"input_descriptors": [
		  {
			"id": "input-1",
			"name": "Example Descriptor",
			"purpose": "Provide proof of identity",
			"format": {
			  "jwt_vc": {
				"alg": ["ES256"]
			  }
			},
			"group": ["A"],
			"constraints": {
			  "limit_disclosure": "required",
			  "fields": [
				{
				  "id": "field-1",
				  "path": ["$.credentialSubject.id"],
				  "name": "Credential Subject ID",
				  "intent_to_retain": true
				}
			  ],
			  "subject_is_issuer": "required"
			}
		  }
		]
	  }
	}`

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

//Generated from schema https://identity.foundation/presentation-exchange/spec/v2.1.1/#presentation-submission-2

// DescriptorFormat represents the allowed format types.
type DescriptorFormat string

const (
	JWT     DescriptorFormat = "jwt"
	JWTVc   DescriptorFormat = "jwt_vc"
	JWTVp   DescriptorFormat = "jwt_vp"
	LDP     DescriptorFormat = "ldp"
	LDPVc   DescriptorFormat = "ldp_vc"
	LDPVp   DescriptorFormat = "ldp_vp"
	MSOMdoc DescriptorFormat = "mso_mdoc"
	ACVc    DescriptorFormat = "ac_vc"
	ACVp    DescriptorFormat = "ac_vp"
	SDJWT   DescriptorFormat = "sd_jwt"
)

// Descriptor represents a descriptor in submission.
type Descriptor struct {
	ID         string           `json:"id"`
	Path       string           `json:"path"`
	PathNested *Descriptor      `json:"path_nested,omitempty"`
	Format     DescriptorFormat `json:"format"`
}

// PresentationSubmission represents a presentation submission.
type PresentationSubmission struct {
	ID            string       `json:"id"`
	DefinitionID  string       `json:"definition_id"`
	DescriptorMap []Descriptor `json:"descriptor_map,minItems=1"`
}

// PresentationSubmissionEnvelope wraps the PresentationSubmission.
type PresentationSubmissionEnvelope struct {
	PresentationSubmission PresentationSubmission `json:"presentation_submission"`
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
		"definition_id": "12345",
		"descriptor_map": [
		  {
			"id": "input-1",
			"path": "$.verifiableCredential[0]",
			"format": "jwt_vc",
			"path_nested": {
			  "id": "nested-1",
			  "path": "$.credentialSubject.id",
			  "format": "jwt_vc"
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

//======================================== COMMON ==================================================

func FromJSON[T any](jsonData string) (*T, error) {
	var obj T
	err := json.Unmarshal([]byte(jsonData), &obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

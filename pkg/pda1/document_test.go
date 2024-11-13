package pda1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func GenerateDocument(t *testing.T) map[string]any {
	document := Document{
		SocialSecurityPin: "12345",
		Nationality:       []string{"SE"},
		DetailsOfEmployment: []DetailsOfEmployment{
			{
				TypeOfEmployment: "01",
				Name:             "SUNET",
				Address: AddressWithCountry{
					Street:   "Tulegatan 11",
					PostCode: "12354",
					Town:     "Stockholm",
					Country:  "SE",
				},
				IDsOfEmployer: []IDsOfEmployer{
					{
						EmployerID: "SE:1234",
						TypeOfID:   "01",
					},
				},
			},
		},
		PlacesOfWork: []PlacesOfWork{
			{
				NoFixedPlaceOfWorkExist: false,
				CountryWork:             "SE",
				PlaceOfWork: []PlaceOfWork{
					{
						CompanyVesselName: "M/S Transpaper",
						FlagStateHomeBase: "Göteborg",
						IDsOfCompany: []IDsOfCompany{
							{
								CompanyID: "SE:1234",
								TypeOfID:  "01",
							},
						},
						Address: Address{
							Street:   "vägen 1",
							PostCode: "1235",
							Town:     "Göteborg",
						},
					},
				},
			},
		},
		DecisionLegislationApplicable: DecisionLegislationApplicable{
			MemberStateWhichLegislationApplies: "SE",
			TransitionalRuleApply:              false,
			StartingDate:                       "1970-01-01",
			EndingDate:                         "2038-01-19",
		},
		StatusConfirmation:           "02",
		UniqueNumberOfIssuedDocument: "SE1234",
		CompetentInstitution: CompetentInstitution{
			InstitutionID:   "SE:12345",
			InstitutionName: "test",
			CountryCode:     "SE",
		},
	}

	b, err := json.Marshal(document)
	assert.NoError(t, err)

	fmt.Println("Document", string(b))

	docMap := map[string]any{}

	err = json.Unmarshal(b, &docMap)
	assert.NoError(t, err)

	return docMap
}

var mockPDA1JSON = `{
	"person": {
		"forename": "Magnus",
		"family_name": "Svensson",
		"date_of_birth": "1986-02-23",
		"other_elements": {
			"sex": "01",
			"forename_at_birth": "Magnus",
			"family_name_at_birth": "Svensson"
		}
	},
	"social_security_pin": "12345",
	"nationality": [
		"SE"
	],
	"details_of_employment": [
		{
			"type_of_employment": "01",
			"name": "SUNET",
			"address": {
				"street": "Tulegatan 11",
				"post_code": "12354",
				"town": "Stockholm",
				"country": "SE"
			},
			"ids_of_employer": [
				{
					"employer_id": "SE:1234",
					"type_of_id": "01"
				}
			]
		}
	],
	"places_of_work": [
		{
			"no_fixed_place_of_work_exist": false,
			"country_work": "SE",
			"place_of_work": [
				{
					"company_vessel_name": "M/S Transpaper",
					"flag_state_home_base": "Göteborg",
					"ids_of_company": [
						{
							"company_id": "SE:1234",
							"type_of_id": "01"
						}
					],
					"address": {
						"street": "vägen 1",
						"post_code": "1235",
						"town": "Göteborg"
					}
				}
			]
		}
	],
	"decision_legislation_applicable": {
		"member_state_which_legislation_applies": "SE",
		"transitional_rule_apply": false,
		"starting_date": "1970-01-01",
		"ending_date": "2038-01-19"
	},
	"status_confirmation": "02",
	"unique_number_of_issued_document": "SE1234",
	"competent_institution": {
		"institution_id": "SE:12345",
		"institution_name": "test",
		"country_code": "SE"
	}
}`

var mockEmptyPDA1JSON = `{}`

var mockTopLevelPDA1JSON = `{
"social_security_pin": "",
		"details_of_employment": "",
		"unique_number_of_issued_document": "",
		"competent_institution": "",
		"nationality": "",
		"places_of_work": "",
		"decision_legislation_applicable": "",
		"status_confirmation": ""
}`

func mockPDA1Map(t *testing.T, jsonString string) map[string]any {
	docMap := map[string]any{}

	err := json.Unmarshal([]byte(jsonString), &docMap)
	assert.NoError(t, err)

	//fmt.Println("Document", docMap)

	return docMap
}

func TestSchemaValidation(t *testing.T) {
	tts := []struct {
		name    string
		payload *model.CompleteDocument
		want    error
	}{
		{
			name: "from struct to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../standards/schema_pda1.json",
				},
				DocumentData: GenerateDocument(t),
			},
			want: nil,
		},
		{
			name: "from string to map",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../standards/schema_pda1.json",
				},
				DocumentData: mockPDA1Map(t, mockPDA1JSON),
			},
			want: nil,
		},
		{
			name: "empty document",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../standards/schema_pda1.json",
				},
				DocumentData: mockPDA1Map(t, mockEmptyPDA1JSON),
			},
			want: &helpers.Error{
				Title: "document_data_schema_error",
				Err: []map[string]any{
					{
						"location": "/details_of_employment",
						"message":  map[string]any{"type_mismatch": "Value is null but should be array"},
					},
					{
						"location": "/places_of_work",
						"message":  map[string]any{"type_mismatch": "Value is null but should be array"},
					},
					{
						"location": "/decision_legislation_applicable",
						"message":  map[string]any{"type_mismatch": "Value is null but should be object"},
					},
					{
						"location": "/status_confirmation",
						"message":  map[string]any{"ref_mismatch": "Value does not match the reference schema"},
					},
					{
						"location": "/unique_number_of_issued_document",
						"message":  map[string]any{"ref_mismatch": "Value does not match the reference schema"},
					},
					{
						"location": "/competent_institution",
						"message":  map[string]any{"type_mismatch": "Value is null but should be object"},
					},
					{
						"location": "/social_security_pin",
						"message":  map[string]any{"type_mismatch": "Value is null but should be string"},
					},
					{
						"location": "/nationality",
						"message":  map[string]any{"type_mismatch": "Value is null but should be array"},
					},
				},
			},
		},
		{
			name: "top level",
			payload: &model.CompleteDocument{
				Meta: &model.MetaData{
					DocumentDataValidationRef: "file://../../standards/schema_pda1.json",
				},
				DocumentData: mockPDA1Map(t, mockTopLevelPDA1JSON),
			},
			want: &helpers.Error{
				Title: "document_data_schema_error",
				Err: []map[string]any{
					{
						"location": "/status_confirmation",
						"message":  map[string]any{"ref_mismatch": "Value does not match the reference schema"},
					},
					{
						"location": "/decision_legislation_applicable",
						"message":  map[string]any{"type_mismatch": "Value is string but should be object"},
					},
					{
						"location": "/places_of_work",
						"message":  map[string]any{"type_mismatch": "Value is string null should be array"},
					},
					{
						"location": "/unique_number_of_issued_document",
						"message":  map[string]any{"ref_mismatch": "Value does not match the reference schema"},
					},
					{
						"location": "/competent_institution",
						"message":  map[string]any{"ref_mismatch": "Value does not match the reference schema"},
					},
					{
						"location": "/nationality",
						"message":  map[string]any{"type_mismatch": "Value is null but should be array"},
					},
					{
						"location": "/details_of_employment",
						"message":  map[string]any{"type_mismatch": "Value is string but should be array"},
					},
					{
						"location": "/social_security_pin",
						"message":  map[string]any{"type_mismatch": "Value is null but should be string"},
					},
					{
						"location": "/unique_number_of_issued_document",
						"message":  map[string]any{"type_mismatch": "Value is string but should be number"},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			got := helpers.ValidateDocumentData(ctx, tt.payload, logger.NewSimple("test"))

			//assert.Equal(t, tt.want, got)
			//opt := func(a, b string) bool { return a < b }
			//if eq := cmp.Equal(tt.want, got); !eq {
			//	//t.Errorf("ValidateDocumentData() mismatch (-want +got):\n%s", cmp.Diff(tt.want, got))
			//	t.Fail()
			//}
			//slices.Equal(tt.want, got)
			if errors.Is(tt.want, got) {
				t.Error("validation failed")
			}

			//	if diff := cmp.Diff(tt.want, got); diff != "" {
			//		t.Errorf("ValidateDocumentData() mismatch (-want +got):\n%s", diff)
			//		assert.Equal(t, tt.want, got)
			//	}

			//assert.ObjectsAreEqual(tt.want, got)
		})
	}
}

package apiv1

import (
	"context"
	"testing"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestBootstrapperConstructor(t *testing.T) {
	tts := []struct {
		name string
		want []uploadMock
	}{
		{
			name: "OK",
			want: []uploadMock{
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_se",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_10",
						RealData:        false,
						Collect: &model.Collect{
							ID:         "collect_id_10",
							ValidUntil: 2147520172,
						},
						Revocation: &model.Revocation{
							ID:      "9da40dc0-9dd4-11ef-9569-efda8acf5ac4",
							Revoked: false,
							Reference: model.RevocationReference{
								AuthenticSource: "authentic_source_se",
								DocumentType:    "EHIC",
								DocumentID:      "document_id_10",
							},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "10",
							Schema: &model.IdentitySchema{
								Name:    "SE",
								Version: "1.0.0",
							},
							FamilyName: "Castaneda",
							GivenName:  "Carlos",
							BirthDate:  "1970-01-10",
						},
					},
					DocumentDisplay: &model.DocumentDisplay{
						Version: "1.0.0",
						Type:    "EHIC",
						DescriptionStructured: map[string]any{
							"en": "issuer",
							"sv": "utfärdare",
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"institution_country": "SE",
							"institution_id":      "SE:1234",
							"institution_name":    "institution_name_se",
						},
						"document_id": "document_id_10",
						"period_entitlement": map[string]any{
							"ending_date":   "2038-01-19",
							"starting_date": "1970-01-01",
						},
						"social_security_pin": "12345",
						"subject": map[string]any{
							"date_of_birth": "1970-01-10",
							"family_name":   "Castaneda",
							"forename":      "Carlos",
							"other_elements": map[string]any{
								"family_name_at_birth": "Castaneda",
								"forename_at_birth":    "Carlos",
								"sex":                  "01",
							},
						},
					},
					DocumentDataVersion: "1.0.0",
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_at",
						DocumentVersion: "1.0.0",
						DocumentType:    "EHIC",
						DocumentID:      "document_id_11",
						RealData:        false,
						Collect: &model.Collect{
							ID:         "collect_id_11",
							ValidUntil: 2147520172,
						},
						Revocation: &model.Revocation{
							ID:      "9da40dc0-9dd4-11ef-9569-efda8acf5ac4",
							Revoked: false,
							Reference: model.RevocationReference{
								AuthenticSource: "authentic_source_at",
								DocumentType:    "EHIC",
								DocumentID:      "document_id_11",
							},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "11",
							Schema: &model.IdentitySchema{
								Name:    "AT",
								Version: "1.0.0",
							},
							FamilyName: "Howell",
							GivenName:  "Lenna",
							BirthDate:  "1935-02-21",
						},
					},
					DocumentDisplay: &model.DocumentDisplay{
						Version: "1.0.0",
						Type:    "EHIC",
						DescriptionStructured: map[string]any{
							"en": "issuer",
							"sv": "utfärdare",
						},
					},
					DocumentData: map[string]any{
						"competent_institution": map[string]any{
							"institution_country": "AT",
							"institution_id":      "AT:1234",
							"institution_name":    "institution_name_at",
						},
						"document_id": "document_id_11",
						"period_entitlement": map[string]any{
							"ending_date":   "2038-01-19",
							"starting_date": "1970-01-01",
						},
						"social_security_pin": "12357",
						"subject": map[string]any{
							"date_of_birth": "1935-02-21",
							"family_name":   "Howell",
							"forename":      "Lenna",
							"other_elements": map[string]any{
								"family_name_at_birth": "Howell",
								"forename_at_birth":    "Lenna",
								"sex":                  "02",
							},
						},
					},
					DocumentDataVersion: "1.0.0",
				},
				{
					Meta: &model.MetaData{
						AuthenticSource: "authentic_source_dk",
						DocumentVersion: "1.0.0",
						DocumentType:    "PDA1",
						DocumentID:      "document_id_20",
						RealData:        false,
						Collect: &model.Collect{
							ID:         "collect_id_20",
							ValidUntil: 2147520172,
						},
						Revocation: &model.Revocation{
							ID:      "9da40dc0-9dd4-11ef-9569-efda8acf5ac4",
							Revoked: false,
							Reference: model.RevocationReference{
								AuthenticSource: "authentic_source_dk",
								DocumentType:    "PDA1",
								DocumentID:      "document_id_20",
							},
							RevokedAt: 0,
							Reason:    "",
						},
						CredentialValidFrom:       1,
						CredentialValidTo:         2147520172,
						DocumentDataValidationRef: "",
					},
					Identities: []model.Identity{
						{
							AuthenticSourcePersonID: "20",
							Schema: &model.IdentitySchema{
								Name:    "DK",
								Version: "1.0.0",
							},
							FamilyName: "Christiansen",
							GivenName:  "Mats",
							BirthDate:  "1983-03-27",
						},
					},
					DocumentData: map[string]any{
						"person": map[string]any{
							"date_of_birth": "1983-03-27",
							"family_name":   "Christiansen",
							"forename":      "Mats",
							"other_elements": map[string]any{
								"family_name_at_birth": "Christiansen",
								"forename_at_birth":    "Mats",
								"sex":                  "01",
							},
						},
						"competent_institution": map[string]any{
							"country_code":     "DK",
							"institution_id":   "DK:1234",
							"institution_name": "institution_name_dk",
						},
						"decision_legislation_applicable": map[string]any{
							"ending_date":                            "2038-01-19",
							"starting_date":                          "1970-01-01",
							"member_state_which_legislation_applies": "DK",
							"transitional_rule_apply":                false,
						},
						"places_of_work": []any{
							map[string]any{
								"no_fixed_place_of_work_exist": false,
								"country_work":                 "DK",
								"place_of_work": []any{
									map[string]any{
										"flag_state_home_base": "DK",
										"company_vessel_name":  "vessel_name_dk",
										"address": map[string]any{
											"street":    "Møllestien 2",
											"post_code": "12332",
											"town":      "Aarhus",
										},
										"ids_of_company": []any{
											map[string]any{
												"company_id": "3615c840-9da4-11ef-ab82-5bd130b1f1e2",
												"type_of_id": "01",
											},
										},
									},
								},
							},
						},
						"details_of_employment": []any{
							map[string]any{
								"name":               "Corp inc.",
								"type_of_employment": "01",
								"address": map[string]any{
									"country":   "DK",
									"post_code": "12332",
									"street":    "Møllestien 2",
									"town":      "Aarhus",
								},
								"ids_of_employer": []any{
									map[string]any{
										"employer_id": "f7c317dc-9da3-11ef-ad15-2ff7d0db967b",
										"type_of_id":  "01",
									},
								},
							},
						},
						"social_security_pin":              "98123",
						"nationality":                      []any{"DK"},
						"status_confirmation":              "01",
						"unique_number_of_issued_document": "asd123",
					},
					DocumentDataVersion: "1.0.0",
					DocumentDisplay: &model.DocumentDisplay{
						Version: "1.0.0",
						Type:    "PDA1",
						DescriptionStructured: map[string]any{
							"en": "issuer",
							"sv": "utfärdare",
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				deterministicMocks: []uploadMock{},
			}

			err := c.bootstrapperConstructor(context.Background())
			assert.NoError(t, err)

			assert.Equal(t, tt.want, c.deterministicMocks)

			for _, mock := range c.deterministicMocks {
				if err := helpers.CheckSimple(mock); err != nil {
					t.Errorf("CheckSimple failed %v", err)
				}
			}

		})
	}
}
